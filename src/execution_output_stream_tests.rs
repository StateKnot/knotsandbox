#![allow(clippy::unwrap_used)]
use super::*;
use serde_json::json;

#[path = "execution_output_stream_http_tests.rs"]
mod http;

fn actor() -> Actor {
    Actor {
        authorization: None,
        tenant_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
    }
}
fn head() -> Head {
    Head {
        project_id: Uuid::new_v4(),
        cluster_epoch: Uuid::new_v4(),
        dispatch_attempt_id: Some(Uuid::new_v4()),
        last_segment: 1,
        output_status: "PARTIAL".into(),
        writer_closed: false,
    }
}
fn position(h: &Head) -> Position {
    Position {
        cluster_epoch: h.cluster_epoch,
        attempt: h.dispatch_attempt_id,
        after: 1,
    }
}
fn page() -> ExecutionOutputPage {
    ExecutionOutputPage {
        execution_id: Uuid::new_v4(),
        snapshot_at: Utc::now(),
        output_status: "PARTIAL".into(),
        manifest_verified: false,
        has_more: false,
        final_segment_sequence: None,
        segments: vec![],
        next_after_segment: None,
    }
}

#[test]
fn resume_cursor_binds_identity_attempt_and_expiry() -> anyhow::Result<()> {
    let actor = actor();
    let id = Uuid::new_v4();
    let now = Utc::now();
    let signer =
        CursorSigner::from_json(include_str!("../tests/fixtures/history/cursor-keys.json"))?;
    let token = position(&head())
        .cursor(&actor, id, &signer, now)
        .map_err(|e| anyhow::anyhow!(e.code))?;
    let mut c: Cursor = signer
        .decode_payload(&token)
        .map_err(|e| anyhow::anyhow!(e.code))?;
    validate_cursor(&c, &actor, id, now).map_err(|e| anyhow::anyhow!(e.code))?;
    assert_eq!(
        validate_cursor(&c, &actor, id, now + chrono::Duration::days(1))
            .unwrap_err()
            .code,
        "OUTPUT_CURSOR_EXPIRED"
    );
    assert!(validate_cursor(&c, &actor, Uuid::new_v4(), now).is_err());
    let mut other = actor.clone();
    other.tenant_id = Uuid::new_v4();
    assert!(validate_cursor(&c, &other, id, now).is_err());
    other = actor.clone();
    other.principal_id = Uuid::new_v4();
    assert!(validate_cursor(&c, &other, id, now).is_err());
    c.kind = "project_event_stream".into();
    assert!(validate_cursor(&c, &actor, id, now).is_err());
    c.kind = "execution_output_stream".into();
    c.dispatch_attempt_id = None;
    assert!(validate_cursor(&c, &actor, id, now).is_err());
    c.after_segment = -1;
    assert!(validate_cursor(&c, &actor, id, now).is_ok());
    c.expires_at += chrono::Duration::seconds(1);
    assert!(validate_cursor(&c, &actor, id, now).is_err());
    assert!(
        signer
            .decode_payload::<Cursor>(&format!("{token}x"))
            .is_err()
    );
    assert!(serde_json::from_value::<StreamQuery>(json!({"access_token":"PRIVATE"})).is_err());
    assert!(serde_json::from_value::<StreamQuery>(json!({"after_segment":100})).is_err());
    Ok(())
}

#[test]
fn output_cursor_future_issue_skew_is_bounded_without_expiry_or_ttl_grace() -> anyhow::Result<()> {
    let actor = actor();
    let id = Uuid::new_v4();
    let position = position(&head());
    let signer =
        CursorSigner::from_json(include_str!("../tests/fixtures/history/cursor-keys.json"))?;
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    for seconds in [1, 60] {
        let token = position
            .cursor(
                &actor,
                id,
                &signer,
                now + chrono::Duration::seconds(seconds),
            )
            .map_err(|e| anyhow::anyhow!(e.code))?;
        let cursor: Cursor = signer
            .decode_payload(&token)
            .map_err(|e| anyhow::anyhow!(e.code))?;
        validate_cursor(&cursor, &actor, id, now).map_err(|e| anyhow::anyhow!(e.code))?;
    }
    let token = position
        .cursor(
            &actor,
            id,
            &signer,
            now + chrono::Duration::seconds(60) + chrono::Duration::nanoseconds(1),
        )
        .map_err(|e| anyhow::anyhow!(e.code))?;
    let cursor: Cursor = signer
        .decode_payload(&token)
        .map_err(|e| anyhow::anyhow!(e.code))?;
    let error = validate_cursor(&cursor, &actor, id, now).unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "INVALID_CURSOR");

    let token = position
        .cursor(
            &actor,
            id,
            &signer,
            now - chrono::Duration::seconds(CURSOR_TTL),
        )
        .map_err(|e| anyhow::anyhow!(e.code))?;
    let cursor: Cursor = signer
        .decode_payload(&token)
        .map_err(|e| anyhow::anyhow!(e.code))?;
    validate_cursor(&cursor, &actor, id, now - chrono::Duration::nanoseconds(1))
        .map_err(|e| anyhow::anyhow!(e.code))?;
    let error = validate_cursor(&cursor, &actor, id, now).unwrap_err();
    assert_eq!(error.status, StatusCode::GONE);
    assert_eq!(error.code, "OUTPUT_CURSOR_EXPIRED");

    let token = position
        .cursor(&actor, id, &signer, now + chrono::Duration::seconds(60))
        .map_err(|e| anyhow::anyhow!(e.code))?;
    let mut cursor: Cursor = signer
        .decode_payload(&token)
        .map_err(|e| anyhow::anyhow!(e.code))?;
    cursor.expires_at += chrono::Duration::nanoseconds(1);
    let error = validate_cursor(&cursor, &actor, id, now).unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "INVALID_CURSOR");
    Ok(())
}

#[test]
fn only_unstarted_position_adopts_first_attempt_and_restored_epoch_never_resumes() {
    let mut h = head();
    h.dispatch_attempt_id = None;
    h.last_segment = -1;
    let mut p = Position {
        cluster_epoch: h.cluster_epoch,
        attempt: None,
        after: -1,
    };
    assert!(validate_position(&mut p, &h).is_ok());
    h.dispatch_attempt_id = Some(Uuid::new_v4());
    assert!(validate_position(&mut p, &h).is_ok());
    assert_eq!(p.attempt, h.dispatch_attempt_id);
    h.dispatch_attempt_id = Some(Uuid::new_v4());
    assert_eq!(
        validate_position(&mut p, &h).unwrap_err().code,
        "OUTPUT_HISTORY_UNAVAILABLE"
    );
    h.dispatch_attempt_id = p.attempt;
    h.cluster_epoch = Uuid::new_v4();
    assert_eq!(
        validate_position(&mut p, &h).unwrap_err().code,
        "OUTPUT_HISTORY_UNAVAILABLE"
    );
    h.cluster_epoch = p.cluster_epoch;
    p.after = 0;
    assert_eq!(
        validate_position(&mut p, &h).unwrap_err().code,
        "OUTPUT_CURSOR_AHEAD"
    );
}

#[test]
fn ending_requires_closed_writer_and_verified_complete_index_not_empty_poll() {
    let mut h = head();
    let p = position(&h);
    let mut page = page();
    assert!(!drained(&page, &h, &p).unwrap());
    h.writer_closed = true;
    assert!(drained(&page, &h, &p).unwrap()); // Explicit PARTIAL, never COMPLETE.
    page.output_status = "COMPLETE".into();
    assert!(!drained(&page, &h, &p).unwrap()); // Completion committed during read.
    h.output_status = "COMPLETE".into();
    assert_eq!(
        drained(&page, &h, &p).unwrap_err().code,
        "OUTPUT_INTEGRITY_FAILED"
    );
    page.manifest_verified = true;
    page.final_segment_sequence = Some(0);
    assert!(drained(&page, &h, &p).is_err());
    page.final_segment_sequence = Some(1);
    assert!(drained(&page, &h, &p).unwrap());
    h.last_segment = 2;
    assert!(!drained(&page, &h, &p).unwrap());
    h.last_segment = 1;
    page.has_more = true;
    assert!(!drained(&page, &h, &p).unwrap());
    page.has_more = false;
    h.output_status = "PENDING".into();
    page.output_status = "PENDING".into();
    assert!(!drained(&page, &h, &p).unwrap());
}
