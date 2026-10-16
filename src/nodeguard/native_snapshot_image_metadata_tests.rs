// Additional fixed Stat/Info messages share the existing real HTTP/2 fixture.
// The server creates no filesystem snapshot and certifies no unpack operation.
const TWO_LAYER_CHAIN: &str =
    "sha256:ccd722928bd92476ba1745586fed6e45a102504185ad88cd89e01ff116fd146c";

fn snapshot_fixture_chain(fault: Fault) -> RootfsChain {
    let first = format!("sha256:{}", "a".repeat(64));
    if fault == Fault::SnapshotTwoLayers {
        RootfsChain {
            chain_id: TWO_LAYER_CHAIN.into(),
            parent_chain_id: Some(first),
        }
    } else {
        RootfsChain {
            chain_id: first,
            parent_chain_id: None,
        }
    }
}

fn snapshot_stamp() -> wire::google::protobuf::Timestamp {
    wire::google::protobuf::Timestamp {
        seconds: 1_700_000_000,
        nanos: 123,
    }
}

fn snapshot_labels(fault: Fault) -> HashMap<String, String> {
    let mut labels = HashMap::from([("private".into(), PRIVATE.into())]);
    match fault {
        Fault::SnapshotLabelCount | Fault::ConfigReferenceLabelCount => {
            for index in 0..MAX_LABELS {
                labels.insert(format!("private-{index}"), PRIVATE.into());
            }
        }
        Fault::SnapshotLabelBytes | Fault::ConfigReferenceLabelBytes => {
            // Each pair obeys the upstream 4096-byte bound, while their sum
            // exceeds the adapter's separate total label budget.
            for index in 0..13 {
                let key = format!("private-{index}");
                labels.insert(key.clone(), "x".repeat(4096 - key.len()));
            }
        }
        Fault::SnapshotLabelPair | Fault::ConfigReferenceLabelPair => {
            labels.insert("pair".into(), "x".repeat(4097));
        }
        Fault::SnapshotOversizedReply => {
            labels.insert("oversized".into(), "x".repeat(SMALL_REPLY + 1));
        }
        _ => {}
    }
    labels
}

fn snapshot_config_info(state: &State, call: usize, info: &mut content::Info) {
    info.created_at = Some(snapshot_stamp());
    info.updated_at = Some(snapshot_stamp());
    info.labels = snapshot_labels(if call > 0 { state.fault } else { Fault::None });
    info.labels.insert(
        SNAPSHOT_REFERENCE_LABEL.into(),
        snapshot_fixture_chain(state.fault).chain_id,
    );
    // The first Info is the pre-existing shared metadata reader. Only the
    // dedicated A/B observations exercise the new reference failure paths.
    if call == 0 {
        return;
    }
    match state.fault {
        Fault::ConfigReferenceMissing => {
            info.labels.remove(SNAPSHOT_REFERENCE_LABEL);
        }
        Fault::ConfigReferenceWrong => {
            info.labels
                .insert(SNAPSHOT_REFERENCE_LABEL.into(), PRIVATE.into());
        }
        Fault::ConfigReferenceChanged if call > 1 => {
            info.labels
                .insert(SNAPSHOT_REFERENCE_LABEL.into(), PRIVATE.into());
        }
        Fault::ConfigReferenceTimeChanged if call > 1 => {
            info.updated_at = Some(wire::google::protobuf::Timestamp {
                seconds: snapshot_stamp().seconds + 1,
                ..snapshot_stamp()
            });
        }
        Fault::ConfigReferenceDigest => info.digest = PRIVATE.into(),
        Fault::ConfigReferenceSize => info.size += 1,
        Fault::ConfigReferenceMissingTime => info.created_at = None,
        _ => {}
    }
}

#[derive(Clone)]
struct Snapshots(Arc<State>);
impl tonic::server::NamedService for Snapshots {
    const NAME: &'static str = "containerd.services.snapshots.v1.Snapshots";
}
impl tonic::server::UnaryService<snapshots::StatSnapshotRequest> for Snapshots {
    type Response = snapshots::StatSnapshotResponse;
    type Future = Reply<Self::Response>;
    fn call(&mut self, request: Request<snapshots::StatSnapshotRequest>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            state.request(&request, "STAT")?;
            let chain = snapshot_fixture_chain(state.fault);
            if request.get_ref().snapshotter != "overlayfs"
                || request.get_ref().key != chain.chain_id
            {
                return Err(Status::invalid_argument(PRIVATE));
            }
            let call = state.snapshot_gets.fetch_add(1, Ordering::SeqCst);
            match state.fault {
                Fault::SnapshotAbsent => return Err(Status::not_found(PRIVATE)),
                Fault::SnapshotProviderSecret => return Err(Status::internal(PRIVATE)),
                Fault::SnapshotRemoteCancelled => {
                    return Err(Status::cancelled("Timeout expired"));
                }
                Fault::SnapshotMissingInfo => {
                    return Ok(Response::new(snapshots::StatSnapshotResponse {
                        info: None,
                    }));
                }
                Fault::SnapshotDeadline => tokio::time::sleep(Duration::from_secs(3)).await,
                _ => {}
            }
            let mut info = snapshots::Info {
                name: chain.chain_id,
                parent: chain.parent_chain_id.unwrap_or_default(),
                kind: snapshots::Kind::Committed as i32,
                created_at: Some(snapshot_stamp()),
                updated_at: Some(snapshot_stamp()),
                labels: snapshot_labels(state.fault),
            };
            match state.fault {
                Fault::SnapshotWrongName => info.name = PRIVATE.into(),
                Fault::SnapshotWrongParent => info.parent = PRIVATE.into(),
                Fault::SnapshotActive => info.kind = snapshots::Kind::Active as i32,
                Fault::SnapshotView => info.kind = snapshots::Kind::View as i32,
                Fault::SnapshotUnknownKind => info.kind = 999,
                Fault::SnapshotChanged if call > 0 => {
                    info.updated_at = Some(wire::google::protobuf::Timestamp {
                        seconds: snapshot_stamp().seconds + 1,
                        ..snapshot_stamp()
                    });
                }
                Fault::SnapshotMissingTime => info.created_at = None,
                Fault::SnapshotInvalidNanos => {
                    info.updated_at = Some(wire::google::protobuf::Timestamp {
                        nanos: 1_000_000_000,
                        ..snapshot_stamp()
                    });
                }
                Fault::SnapshotInvalidSeconds => {
                    info.updated_at = Some(wire::google::protobuf::Timestamp {
                        seconds: 253_402_300_800,
                        ..snapshot_stamp()
                    });
                }
                Fault::SnapshotReversedTime => {
                    info.updated_at = Some(wire::google::protobuf::Timestamp {
                        seconds: snapshot_stamp().seconds - 1,
                        ..snapshot_stamp()
                    });
                }
                _ => {}
            }
            Ok(Response::new(snapshots::StatSnapshotResponse {
                info: Some(info),
            }))
        })
    }
}
unary_http!(
    Snapshots,
    "/containerd.services.snapshots.v1.Snapshots/Stat",
    snapshots::StatSnapshotRequest,
    snapshots::StatSnapshotResponse
);

async fn actual_snapshot_wire(
    fault: Fault,
    index: bool,
) -> anyhow::Result<(
    Result<NativeSnapshotMetadata, NativeImageMetadataError>,
    Arc<State>,
)> {
    actual_wire_run(fault, index, |channel, state, deadline| async move {
        inspect_snapshot_channel(
            channel,
            &state.fixture.reference,
            &state.fixture.root.digest,
            "linux/amd64",
            deadline,
        )
        .await
    })
    .await
}

#[tokio::test]
async fn actual_snapshot_identity_observes_committed_root_and_reference_without_unpack_authority()
-> anyhow::Result<()> {
    for fault in [Fault::None, Fault::SnapshotTwoLayers] {
        for index in [false, true] {
            let (outcome, state) = actual_snapshot_wire(fault, index).await?;
            let report = serde_json::to_value(outcome?)?;
            let chain = snapshot_fixture_chain(fault);
            ensure!(report["scope"] == "NATIVE_SNAPSHOT_REFERENCE_METADATA_ONLY");
            ensure!(report["snapshotter"] == "overlayfs");
            ensure!(report["chain_id"] == chain.chain_id);
            ensure!(report["parent_chain_id"] == serde_json::to_value(chain.parent_chain_id)?);
            ensure!(report["reference_label_matches"] == true);
            ensure!(report["snapshot_committed_observed"] == true);
            for field in [
                "approval_checked",
                "pull_selection_checked",
                "runtime_handler_checked",
                "layer_payloads_verified",
                "gc_protection_checked",
                "preparation_allowed",
            ] {
                ensure!(
                    report[field] == false,
                    "snapshot metadata cannot establish {field}"
                );
            }
            ensure!(report.get("unpacked").is_none() && report.get("ready").is_none());
            ensure!(report["native"]["metadata"]["config"]["digest"] == state.fixture.config);
            ensure!(report["native"]["metadata"]["layer_payloads_verified"] == false);
            ensure!(!report.to_string().contains(PRIVATE));
            let mut expected = vec!["VERSION", "GET", "INFO", "READ"];
            if index {
                expected.extend(["INFO", "READ"]);
            }
            expected.extend(["INFO", "READ", "INFO", "STAT", "STAT", "INFO", "GET"]);
            ensure!(
                *state
                    .calls
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fixture lock"))?
                    == expected
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn actual_snapshot_identity_rejects_missing_conflicting_changed_and_unbounded_metadata()
-> anyhow::Result<()> {
    use NativeImageMetadataError as Error;
    for (fault, expected) in [
        (Fault::SnapshotAbsent, Error::SnapshotUnavailable),
        (Fault::SnapshotMissingInfo, Error::ResponseInvalid),
        (Fault::SnapshotWrongName, Error::SnapshotIdentityMismatch),
        (Fault::SnapshotWrongParent, Error::SnapshotIdentityMismatch),
        (Fault::SnapshotActive, Error::SnapshotIdentityMismatch),
        (Fault::SnapshotView, Error::SnapshotIdentityMismatch),
        (Fault::SnapshotUnknownKind, Error::SnapshotIdentityMismatch),
        (Fault::SnapshotChanged, Error::SnapshotChanged),
        (Fault::SnapshotMissingTime, Error::ResponseInvalid),
        (Fault::SnapshotInvalidNanos, Error::ResponseInvalid),
        (Fault::SnapshotInvalidSeconds, Error::ResponseInvalid),
        (Fault::SnapshotReversedTime, Error::ResponseInvalid),
        (Fault::SnapshotLabelCount, Error::ResponseInvalid),
        (Fault::SnapshotLabelBytes, Error::ResponseInvalid),
        (Fault::SnapshotLabelPair, Error::ResponseInvalid),
        (Fault::SnapshotOversizedReply, Error::ResponseInvalid),
        (Fault::SnapshotProviderSecret, Error::RuntimeUnavailable),
        (Fault::SnapshotRemoteCancelled, Error::RuntimeUnavailable),
        (
            Fault::ConfigReferenceMissing,
            Error::SnapshotReferenceMismatch,
        ),
        (
            Fault::ConfigReferenceWrong,
            Error::SnapshotReferenceMismatch,
        ),
        (
            Fault::ConfigReferenceChanged,
            Error::SnapshotReferenceMismatch,
        ),
        (Fault::ConfigReferenceTimeChanged, Error::SnapshotChanged),
        (Fault::ConfigReferenceDigest, Error::ResponseInvalid),
        (Fault::ConfigReferenceSize, Error::ResponseInvalid),
        (Fault::ConfigReferenceMissingInfo, Error::ResponseInvalid),
        (Fault::ConfigReferenceMissingTime, Error::ResponseInvalid),
        (Fault::ConfigReferenceLabelCount, Error::ResponseInvalid),
        (Fault::ConfigReferenceLabelBytes, Error::ResponseInvalid),
        (Fault::ConfigReferenceLabelPair, Error::ResponseInvalid),
        (Fault::FinalRoot, Error::ImageChanged),
        (Fault::WrongVersion, Error::RuntimeIdentityMismatch),
    ] {
        let (outcome, state) = actual_snapshot_wire(fault, true).await?;
        let error = outcome
            .err()
            .with_context(|| format!("{fault:?} produced a receipt"))?;
        ensure!(
            error == expected,
            "wrong snapshot failure for {fault:?}: {}",
            error.code()
        );
        ensure!(!error.to_string().contains(PRIVATE) && error.to_string() == error.code());
        if matches!(
            fault,
            Fault::ConfigReferenceMissing | Fault::ConfigReferenceWrong
        ) {
            ensure!(state.snapshot_gets.load(Ordering::SeqCst) == 0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn actual_snapshot_identity_does_not_query_an_empty_rootfs_snapshot_key() -> anyhow::Result<()>
{
    let (outcome, state) = actual_snapshot_wire(Fault::SnapshotZeroLayers, true).await?;
    ensure!(matches!(
        outcome,
        Err(NativeImageMetadataError::SnapshotNotApplicable)
    ));
    ensure!(state.snapshot_gets.load(Ordering::SeqCst) == 0);
    ensure!(state.config_info_gets.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn actual_snapshot_identity_shares_the_original_five_second_budget_and_retires_io()
-> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let (outcome, state) = actual_snapshot_wire(Fault::SnapshotDeadline, false).await?;
    ensure!(matches!(
        outcome,
        Err(NativeImageMetadataError::DeadlineExceeded)
    ));
    ensure!(
        started.elapsed() >= Duration::from_secs(4) && started.elapsed() < Duration::from_secs(6)
    );
    ensure!(state.snapshot_gets.load(Ordering::SeqCst) == 2);
    ensure!(state.config_info_gets.load(Ordering::SeqCst) == 2);
    ensure!(state.gets.load(Ordering::SeqCst) == 1);
    Ok(())
}
