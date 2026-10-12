//! One Kubernetes v5 CONNECT; bounded full-duplex bytes and trusted channel 3.
use super::{
    ledger::PreparedFileTransfer,
    protocol::{DecodedFileEvent, FileDecoder, FileFailureCode, MAX_WIRE_BYTES},
};
use crate::{
    file_store::OssFileWriter, gateway_protocol::process_exit_from_kubernetes_status,
    runtime_manifest::container_name,
};
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
#[derive(Debug, thiserror::Error)]
#[error("file connection interrupted; no automatic replay is permitted")]
pub struct FileTransportError;
pub enum FileTerminal {
    Complete { byte_length: u64, sha256: String },
    Error(FileFailureCode),
}
pub struct CompletedFileProcess {
    pub trusted_exit_code: i32,
    pub terminal: FileTerminal,
}
pub async fn execute_file_once(
    client: Client,
    p: &PreparedFileTransfer,
    reader: &OssFileWriter,
    output: mpsc::Sender<Vec<u8>>,
) -> Result<CompletedFileProcess, FileTransportError> {
    let remaining = (p.deadline - chrono::Utc::now())
        .to_std()
        .map_err(|_| FileTransportError)?;
    if remaining.is_zero() || remaining.as_secs() > 300 {
        return Err(FileTransportError);
    }
    p.request
        .validate(super::protocol::FileBinding {
            transfer_id: p.request.transfer_id,
            dispatch_attempt_id: p.request.dispatch_attempt_id,
        })
        .map_err(|_| FileTransportError)?;
    let mut header = serde_json::to_vec(&p.request).map_err(|_| FileTransportError)?;
    header.push(b'\n');
    if header.len() > 16 * 1024 {
        return Err(FileTransportError);
    }
    let pods: Api<Pod> = Api::namespaced(client.clone(), &p.namespace);
    let params = AttachParams {
        container: Some(container_name(p.identity.launch_id)),
        stdin: true,
        stdout: true,
        stderr: true,
        tty: false,
        ..Default::default()
    };
    let command = [
        "/usr/local/bin/sandbox-runner".into(),
        "file-transfer".into(),
        "--transfer-id".into(),
        p.request.transfer_id.to_string(),
        "--dispatch-attempt-id".into(),
        p.request.dispatch_attempt_id.to_string(),
    ];
    let request = kube::core::Request::new(pods.resource_url())
        .exec(&p.pod_name, command, &params)
        .map_err(|_| FileTransportError)?;
    tokio::time::timeout(remaining, async {
        let connection = client
            .connect(request)
            .await
            .map_err(|_| FileTransportError)?;
        if !connection.supports_stream_close() {
            return Err(FileTransportError);
        }
        let io = connection.into_stream().into_inner();
        let stream = WebSocketStream::from_raw_socket(io, Role::Client, Some(config())).await;
        exchange(stream, p, reader, header, output).await
    })
    .await
    .map_err(|_| FileTransportError)?
}
fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(8192)
        .write_buffer_size(0)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(64 * 1024))
        .max_frame_size(Some(64 * 1024))
}
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: WebSocketStream<S>,
    p: &PreparedFileTransfer,
    reader: &OssFileWriter,
    header: Vec<u8>,
    output: mpsc::Sender<Vec<u8>>,
) -> Result<CompletedFileProcess, FileTransportError> {
    let (mut send, mut receive) = stream.split();
    let write = async {
        async fn send_bytes<S: AsyncRead + AsyncWrite + Unpin>(
            send: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
            bytes: &[u8],
        ) -> Result<(), FileTransportError> {
            for chunk in bytes.chunks(32 * 1024) {
                let mut message = Vec::with_capacity(chunk.len() + 1);
                message.push(0);
                message.extend_from_slice(chunk);
                send.send(Message::Binary(message.into()))
                    .await
                    .map_err(|_| FileTransportError)?;
            }
            Ok(())
        }
        send_bytes(&mut send, &header).await?;
        for part in &p.parts {
            let bytes = reader
                .read_part(part)
                .await
                .map_err(|_| FileTransportError)?;
            send_bytes(&mut send, &bytes).await?;
        }
        send.send(Message::Binary(vec![255, 0].into()))
            .await
            .map_err(|_| FileTransportError)?;
        Ok::<_, FileTransportError>(())
    };
    let read = async {
        let mut decoder = FileDecoder::new(&p.request).map_err(|_| FileTransportError)?;
        let mut status = Vec::new();
        let mut terminal = None;
        let mut closed = [false; 4];
        let mut count = 0_u64;
        let mut wire = 0_u64;
        while let Some(message) = receive.next().await {
            let message = message.map_err(|_| FileTransportError)?;
            count += 1;
            wire = wire.saturating_add(message.len() as u64);
            if count > 100_000 || wire > MAX_WIRE_BYTES + 1024 * 1024 {
                return Err(FileTransportError);
            }
            match message {
                Message::Binary(bytes) => {
                    let (&channel, payload) = bytes.split_first().ok_or(FileTransportError)?;
                    match channel {
                        1 if !closed[1] => {
                            for event in decoder.push(payload).map_err(|_| FileTransportError)? {
                                match event {
                                    DecodedFileEvent::Started => {}
                                    DecodedFileEvent::Data { bytes, .. } => {
                                        output.send(bytes).await.map_err(|_| FileTransportError)?
                                    }
                                    DecodedFileEvent::Complete {
                                        byte_length,
                                        sha256,
                                    } => {
                                        terminal = Some(FileTerminal::Complete {
                                            byte_length,
                                            sha256,
                                        })
                                    }
                                    DecodedFileEvent::Error(code) => {
                                        terminal = Some(FileTerminal::Error(code))
                                    }
                                }
                            }
                        }
                        2 if !closed[2] && payload.is_empty() => {}
                        3 if !closed[3] => {
                            if status.len() + payload.len() > 16 * 1024 {
                                return Err(FileTransportError);
                            }
                            status.extend_from_slice(payload);
                        }
                        255 if payload.len() == 1 && (1..=3).contains(&payload[0]) => {
                            let i = payload[0] as usize;
                            if closed[i] {
                                return Err(FileTransportError);
                            }
                            closed[i] = true;
                        }
                        _ => return Err(FileTransportError),
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                _ => return Err(FileTransportError),
            }
        }
        decoder.finish().map_err(|_| FileTransportError)?;
        let status: Status = serde_json::from_slice(&status).map_err(|_| FileTransportError)?;
        let trusted_exit_code =
            process_exit_from_kubernetes_status(&status).ok_or(FileTransportError)?;
        Ok(CompletedFileProcess {
            trusted_exit_code,
            terminal: terminal.ok_or(FileTransportError)?,
        })
    };
    let (_, completed) = tokio::try_join!(write, read)?;
    Ok(completed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::{
        file_store::{OssFileConfig, OssFileWriter},
        file_transfer::{
            path::RelativeFilePath,
            protocol::{FileBinding, FileDirection, FileEvent, FileRequest, encode_frame},
        },
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;
    async fn fixture(
        status: bool,
        wrong_identity: bool,
        huge: bool,
    ) -> Result<CompletedFileProcess, FileTransportError> {
        let transfer = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let request = FileRequest {
            protocol_version: 1,
            transfer_id: transfer,
            dispatch_attempt_id: attempt,
            direction: FileDirection::Download,
            path: RelativeFilePath::new("download.bin".into()).unwrap(),
            byte_limit: 3,
            expected_length: None,
            expected_sha256: None,
            replace: false,
        };
        let prepared = PreparedFileTransfer {
            request,
            namespace: "fixture".into(),
            pod_name: "fixture".into(),
            identity: crate::execution::DispatchIdentity {
                runtime_generation: 1,
                launch_id: Uuid::new_v4(),
                pod_uid: Uuid::new_v4(),
                cluster_epoch: Uuid::new_v4(),
            },
            deadline: chrono::Utc::now() + chrono::Duration::seconds(60),
            parts: vec![],
        };
        let writer = OssFileWriter::new(OssFileConfig {
            endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
            bucket: "sandbox-files".into(),
            kms_key_id: "test-kms".into(),
            sts_credentials_file: std::path::PathBuf::from("/unread-fixture-file"),
        })
        .unwrap();
        let (a, b) = tokio::io::duplex(256 * 1024);
        let client = WebSocketStream::from_raw_socket(a, Role::Client, Some(config())).await;
        let mut server = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        let (tx, mut rx) = mpsc::channel(4);
        let body = tokio::spawn(async move {
            let mut got = vec![];
            while let Some(v) = rx.recv().await {
                got.extend(v);
            }
            got
        });
        let task = tokio::spawn(async move {
            let Message::Binary(header) = server.next().await.unwrap().unwrap() else {
                panic!("expected input header")
            };
            assert_eq!(header[0], 0);
            let parsed: FileRequest = serde_json::from_slice(&header[1..]).unwrap();
            assert_eq!(parsed.transfer_id, transfer);
            assert!(
                matches!(server.next().await.unwrap().unwrap(),Message::Binary(b) if b.as_ref()==[255,0])
            );
            let binding = FileBinding {
                transfer_id: if wrong_identity {
                    Uuid::new_v4()
                } else {
                    transfer
                },
                dispatch_attempt_id: attempt,
            };
            if huge {
                let mut frame = vec![1];
                frame.resize(128 * 1024, 42);
                server.send(Message::Binary(frame.into())).await.unwrap();
                return;
            }
            let mut wire = encode_frame(binding, 0, FileEvent::Started).unwrap();
            wire.extend(
                encode_frame(
                    binding,
                    1,
                    FileEvent::Data {
                        offset: 0,
                        data: "YWJj".into(),
                    },
                )
                .unwrap(),
            );
            wire.extend(
                encode_frame(
                    binding,
                    2,
                    FileEvent::Complete {
                        byte_length: 3,
                        sha256: hex::encode(Sha256::digest(b"abc")),
                    },
                )
                .unwrap(),
            );
            for chunk in wire.chunks(17) {
                let mut message = vec![1];
                message.extend_from_slice(chunk);
                if server.send(Message::Binary(message.into())).await.is_err() {
                    return;
                }
            }
            if status {
                let mut message = vec![3];
                message.extend_from_slice(br#"{"status":"Success","code":200}"#);
                if server.send(Message::Binary(message.into())).await.is_err() {
                    return;
                }
            }
            let _ = server.send(Message::Close(None)).await;
        });
        let mut header = serde_json::to_vec(&prepared.request).unwrap();
        header.push(b'\n');
        let result = exchange(client, &prepared, &writer, header, tx).await;
        task.await.unwrap();
        let received = body.await.unwrap();
        if result.is_ok() {
            assert_eq!(received, b"abc");
        }
        result
    }
    #[tokio::test]
    async fn fragmented_download_requires_independent_digest_and_trusted_status() {
        let r = fixture(true, false, false).await.unwrap();
        assert_eq!(r.trusted_exit_code, 0);
        assert!(matches!(
            r.terminal,
            FileTerminal::Complete { byte_length: 3, .. }
        ));
    }
    #[tokio::test]
    async fn guest_complete_without_exec_status_cannot_complete() {
        assert!(fixture(false, false, false).await.is_err());
    }
    #[tokio::test]
    async fn wrong_dispatch_identity_is_rejected() {
        assert!(fixture(true, true, false).await.is_err());
    }
    #[tokio::test]
    async fn websocket_message_limits_are_applied_before_decode() {
        assert!(fixture(true, false, true).await.is_err());
    }
}
