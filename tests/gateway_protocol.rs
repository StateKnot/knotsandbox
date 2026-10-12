use sandbox_platform::{
    gateway_protocol::{
        GuestDecoder, GuestEvent, GuestTerminal, MAX_GUEST_LINE_BYTES,
        process_exit_from_kubernetes_status,
    },
    runner::OutputStream,
};
use serde_json::json;
use uuid::Uuid;
fn line(id: Uuid, seq: u64, event: serde_json::Value) -> Vec<u8> {
    let mut frame = json!({"protocol_version":1,"execution_id":id,"sequence":seq});
    for (k, v) in event.as_object().into_iter().flatten() {
        frame[k] = v.clone();
    }
    let mut bytes = frame.to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}
fn terminal() -> serde_json::Value {
    json!({"type":"exited","exit_code":0,"signal":null,"timed_out":false,"cancelled":false,"output_complete":true,"output_truncated":false,"bytes_observed":3,"bytes_emitted":3,"termination_confirmed":true})
}
#[test]
fn split_binary_frames_have_platform_offsets_and_guest_cannot_attest_vm_death() -> anyhow::Result<()>
{
    let id = Uuid::new_v4();
    let mut parser = GuestDecoder::new(id, 16)?;
    parser.push(&line(id, 0, json!({"type":"started","pid":42})))?;
    let output = line(
        id,
        1,
        json!({"type":"output","stream":"stdout","data":"AP+A"}),
    );
    assert!(parser.push(&output[..7])?.is_empty());
    let events = parser.push(&output[7..])?;
    assert!(
        matches!(&events[0],GuestEvent::Output{sequence:1,stream:OutputStream::Stdout,offset:0,bytes} if bytes==&[0,255,128])
    );
    let events = parser.push(&line(id, 2, terminal()))?;
    assert!(
        matches!(&events[0],GuestEvent::Terminal(GuestTerminal::Exited(s)) if !s.termination_confirmed)
    );
    parser.finish()?;
    Ok(())
}
#[test]
fn independent_output_quota_truncates_without_accepting_runner_claims() -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let mut parser = GuestDecoder::new(id, 1)?;
    parser.push(&line(id, 0, json!({"type":"started","pid":1})))?;
    let events = parser.push(&line(
        id,
        1,
        json!({"type":"output","stream":"stderr","data":"AP+A"}),
    ))?;
    assert!(matches!(&events[0],GuestEvent::Output{bytes,..} if bytes.len()==1));
    assert!(parser.truncated);
    let events = parser.push(&line(id, 2, terminal()))?;
    assert!(
        matches!(&events[0],GuestEvent::Terminal(GuestTerminal::Exited(s)) if s.output_truncated)
    );
    Ok(())
}
#[test]
fn wrong_identity_sequence_and_unknown_fields_fail_closed() -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    for frame in [
        line(Uuid::new_v4(), 0, json!({"type":"started","pid":1})),
        line(id, 1, json!({"type":"started","pid":1})),
        line(
            id,
            0,
            json!({"type":"started","pid":1,"uid_override":"root"}),
        ),
    ] {
        assert!(GuestDecoder::new(id, 16)?.push(&frame).is_err());
    }
    Ok(())
}
#[test]
fn line_and_chunk_allocations_are_bounded_before_parsing() -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    assert!(
        GuestDecoder::new(id, 16)?
            .push(&vec![b'x'; MAX_GUEST_LINE_BYTES + 1])
            .is_err()
    );
    assert!(GuestDecoder::new(id, 16)?.push(&vec![b'x'; 65537]).is_err());
    Ok(())
}
#[test]
fn channel_eof_requires_terminal_and_no_trailing_guest_frames() -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let mut p = GuestDecoder::new(id, 16)?;
    p.push(&line(id, 0, json!({"type":"started","pid":1})))?;
    assert!(p.finish().is_err());
    p.push(&line(
        id,
        1,
        json!({"type":"error","code":"SPAWN_FAILED","termination_confirmed":true}),
    ))?;
    p.finish()?;
    assert!(
        p.push(&line(id, 2, json!({"type":"started","pid":1})))
            .is_err()
    );
    Ok(())
}
#[test]
fn trusted_status_requires_explicit_kubernetes_terminal_shape() -> anyhow::Result<()> {
    assert_eq!(
        process_exit_from_kubernetes_status(&serde_json::from_value(json!({"status":"Success"}))?),
        Some(0)
    );
    assert_eq!(
        process_exit_from_kubernetes_status(&serde_json::from_value(
            json!({"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"64"}]}})
        )?),
        Some(64)
    );
    assert_eq!(
        process_exit_from_kubernetes_status(&serde_json::from_value(
            json!({"status":"Failure","reason":"Forbidden"})
        )?),
        None
    );
    Ok(())
}
