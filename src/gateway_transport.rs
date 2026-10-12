//! At-most-one Kubernetes exec connection per committed dispatch attempt.
//! The caller owns durable dispatch fencing, lease heartbeat and safety STOP.
use futures_util::{SinkExt, StreamExt};
use k8s_openapi::{api::core::v1::Pod, apimachinery::pkg::apis::meta::v1::Status};
use kube::{Api, Client, api::AttachParams};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};

use crate::{
    execution::PreparedExecution,
    gateway_protocol::{
        GuestDecoder, GuestEvent, GuestTerminal, process_exit_from_kubernetes_status,
    },
    runtime_manifest::container_name,
};

#[derive(Debug, thiserror::Error)]
pub enum ExecTransportError {
    #[error("exec transport unavailable or interrupted; dispatch outcome is unknown")]
    Interrupted,
    #[error("exec requires Kubernetes v5 stream-close protocol")]
    UnsupportedProtocol,
    #[error("exec input or guest protocol was rejected")]
    Protocol,
    #[error("exec deadline reached")]
    Deadline,
    #[error("output persistence channel closed")]
    OutputClosed,
}

pub struct CompletedProcess {
    pub trusted_process_exit_code: i32,
    pub guest_terminal: GuestTerminal,
}

/// Invoke only after DISPATCHING commits. Neither this function nor the
/// production Kubernetes client installs a reconnect/retry layer.
pub async fn execute_once(
    client: Client,
    prepared: &PreparedExecution,
    outputs: mpsc::Sender<GuestEvent>,
) -> Result<CompletedProcess, ExecTransportError> {
    let remaining = (prepared.deadline - chrono::Utc::now())
        .to_std()
        .map_err(|_| ExecTransportError::Deadline)?;
    if remaining.is_zero() || remaining.as_secs() > 3600 {
        return Err(ExecTransportError::Deadline);
    }
    let input = serde_json::to_vec(&prepared.request).map_err(|_| ExecTransportError::Protocol)?;
    if input.len() > crate::runner::MAX_INPUT_BYTES || prepared.dispatch_attempt_id.is_nil() {
        return Err(ExecTransportError::Protocol);
    }
    let request = exec_request(client.clone(), prepared)?;
    tokio::time::timeout(remaining, async {
        let connection = client
            .connect(request)
            .await
            .map_err(|_| ExecTransportError::Interrupted)?;
        if !connection.supports_stream_close() {
            return Err(ExecTransportError::UnsupportedProtocol);
        }
        // kube 4.2 creates from_raw_socket without reading any WS message.
        // tokio-tungstenite has no public set_config: unwrap BEFORE first I/O,
        // then reuse that same upgraded transport with strict frame limits.
        let io = connection.into_stream().into_inner();
        let stream =
            WebSocketStream::from_raw_socket(io, Role::Client, Some(bounded_config())).await;
        exchange(
            stream,
            prepared.request.execution_id,
            prepared.request.output_limit_bytes,
            input,
            outputs,
        )
        .await
    })
    .await
    .map_err(|_| ExecTransportError::Deadline)?
}

fn exec_request(
    client: Client,
    prepared: &PreparedExecution,
) -> Result<axum::http::Request<Vec<u8>>, ExecTransportError> {
    let api: Api<Pod> = Api::namespaced(client, &prepared.namespace);
    let params = AttachParams {
        container: Some(container_name(prepared.identity.launch_id)),
        stdin: true,
        stdout: true,
        stderr: true,
        tty: false,
        ..Default::default()
    };
    let command = [
        "/usr/local/bin/sandbox-runner".to_owned(),
        "exec".to_owned(),
        "--execution-id".to_owned(),
        prepared.request.execution_id.to_string(),
        "--dispatch-attempt-id".to_owned(),
        prepared.dispatch_attempt_id.to_string(),
    ];
    kube::core::Request::new(api.resource_url())
        .exec(&prepared.pod_name, command, &params)
        .map_err(|_| ExecTransportError::Protocol)
}

fn bounded_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(8192)
        .write_buffer_size(0)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(64 * 1024))
        .max_frame_size(Some(64 * 1024))
}

async fn exchange<S>(
    mut stream: WebSocketStream<S>,
    execution: uuid::Uuid,
    output_limit: u64,
    input: Vec<u8>,
    outputs: mpsc::Sender<GuestEvent>,
) -> Result<CompletedProcess, ExecTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Keep outbound WS messages bounded too; input EOF is a v5 stream close,
    // never a WebSocket close that would discard the remaining output streams.
    for chunk in input.chunks(32 * 1024) {
        let mut data = Vec::with_capacity(chunk.len() + 1);
        data.push(0);
        data.extend_from_slice(chunk);
        stream
            .send(Message::Binary(data.into()))
            .await
            .map_err(|_| ExecTransportError::Interrupted)?;
    }
    stream
        .send(Message::Binary(vec![255, 0].into()))
        .await
        .map_err(|_| ExecTransportError::Interrupted)?;
    let mut decoder =
        GuestDecoder::new(execution, output_limit).map_err(|_| ExecTransportError::Protocol)?;
    let mut terminal = None;
    let mut status_bytes = Vec::new();
    let mut closed = [false; 4];
    let mut messages = 0_u64;
    let mut wire_bytes = 0_usize;
    while let Some(message) = stream.next().await {
        let message = message.map_err(|_| ExecTransportError::Interrupted)?;
        messages += 1;
        wire_bytes = wire_bytes.saturating_add(message.len());
        if messages > 32768 || wire_bytes > 25 * 1024 * 1024 {
            return Err(ExecTransportError::Protocol);
        }
        match message {
            Message::Binary(data) => {
                let (&channel, payload) = data.split_first().ok_or(ExecTransportError::Protocol)?;
                match channel {
                    1 if !closed[1] => {
                        for event in decoder
                            .push(payload)
                            .map_err(|_| ExecTransportError::Protocol)?
                        {
                            if let GuestEvent::Terminal(result) = event {
                                terminal = Some(result);
                            } else {
                                outputs
                                    .send(event)
                                    .await
                                    .map_err(|_| ExecTransportError::OutputClosed)?;
                            }
                        }
                    }
                    // Runner stderr is not part of the framed workload output.
                    // Never log arbitrary stderr text or treat it as a receipt.
                    2 if !closed[2] && payload.is_empty() => {}
                    3 if !closed[3] => {
                        if status_bytes.len() + payload.len() > 16 * 1024 {
                            return Err(ExecTransportError::Protocol);
                        }
                        status_bytes.extend_from_slice(payload);
                    }
                    255 if payload.len() == 1 && (1..=3).contains(&payload[0]) => {
                        let index = payload[0] as usize;
                        if closed[index] {
                            return Err(ExecTransportError::Protocol);
                        }
                        closed[index] = true;
                    }
                    _ => return Err(ExecTransportError::Protocol),
                }
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
            _ => return Err(ExecTransportError::Protocol),
        }
    }
    decoder.finish().map_err(|_| ExecTransportError::Protocol)?;
    let status: Status =
        serde_json::from_slice(&status_bytes).map_err(|_| ExecTransportError::Interrupted)?;
    let code =
        process_exit_from_kubernetes_status(&status).ok_or(ExecTransportError::Interrupted)?;
    Ok(CompletedProcess {
        trusted_process_exit_code: code,
        guest_terminal: terminal.ok_or(ExecTransportError::Protocol)?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::json;
    use uuid::Uuid;
    async fn exchange_fixture(
        status: bool,
        oversized: bool,
    ) -> Result<CompletedProcess, ExecTransportError> {
        let execution = Uuid::new_v4();
        let (a, b) = tokio::io::duplex(256 * 1024);
        let client =
            WebSocketStream::from_raw_socket(a, Role::Client, Some(bounded_config())).await;
        let mut server = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        let (tx, mut rx) = mpsc::channel(4);
        let server_task = tokio::spawn(async move {
            assert_eq!(
                server.next().await.unwrap().unwrap(),
                Message::Binary(vec![0, b'{', b'}'].into())
            );
            assert_eq!(
                server.next().await.unwrap().unwrap(),
                Message::Binary(vec![255, 0].into())
            );
            if oversized {
                let _ = server
                    .send(Message::Binary(vec![1; 65 * 1024].into()))
                    .await;
                return;
            }
            let frames = [
                json!({"protocol_version":1,"execution_id":execution,"sequence":0,"type":"started","pid":42}),
                json!({"protocol_version":1,"execution_id":execution,"sequence":1,"type":"exited","exit_code":0,"signal":null,"timed_out":false,"cancelled":false,"output_complete":true,"output_truncated":false,"bytes_observed":0,"bytes_emitted":0,"termination_confirmed":true}),
            ];
            for frame in frames {
                let mut bytes = vec![1];
                bytes.extend(serde_json::to_vec(&frame).unwrap());
                bytes.push(b'\n');
                server.send(Message::Binary(bytes.into())).await.unwrap();
            }
            if status {
                let mut bytes = vec![3];
                bytes.extend_from_slice(br#"{"status":"Success"}"#);
                server.send(Message::Binary(bytes.into())).await.unwrap();
            }
            server.close(None).await.unwrap();
        });
        let result = exchange(client, execution, 1024, b"{}".to_vec(), tx).await;
        server_task.await.unwrap();
        if !oversized {
            assert!(matches!(rx.recv().await, Some(GuestEvent::Started)));
        }
        result
    }
    #[tokio::test]
    async fn v5_stdin_eof_keeps_output_open_and_only_status_channel_confirms_process() {
        let completed = exchange_fixture(true, false).await.unwrap();
        assert_eq!(completed.trusted_process_exit_code, 0);
        let GuestTerminal::Exited(report) = completed.guest_terminal else {
            panic!("expected exit")
        };
        assert!(!report.termination_confirmed);
        assert!(matches!(
            exchange_fixture(false, false).await,
            Err(ExecTransportError::Interrupted)
        ));
    }
    #[tokio::test]
    async fn oversized_websocket_message_is_rejected_before_guest_decode() {
        assert!(matches!(
            exchange_fixture(false, true).await,
            Err(ExecTransportError::Interrupted)
        ));
    }
}
