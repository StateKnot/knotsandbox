#![allow(clippy::expect_used)]
#[allow(dead_code, unused_imports)]
#[path = "../src/file_transfer_path.rs"]
mod path;
#[allow(dead_code, unused_imports)]
#[path = "../src/file_transfer_protocol.rs"]
mod protocol;
use base64::{Engine, engine::general_purpose::STANDARD};
use path::RelativeFilePath;
use protocol::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn request(direction: FileDirection) -> FileRequest {
    FileRequest {
        protocol_version: 1,
        transfer_id: Uuid::new_v4(),
        dispatch_attempt_id: Uuid::new_v4(),
        direction,
        path: RelativeFilePath::new("input/data.bin".into()).expect("fixture path"),
        byte_limit: 3,
        expected_length: if direction == FileDirection::Upload {
            Some(3)
        } else {
            None
        },
        expected_sha256: if direction == FileDirection::Upload {
            Some(sha(b"abc"))
        } else {
            None
        },
        replace: false,
    }
}
fn binding(r: &FileRequest) -> FileBinding {
    FileBinding {
        transfer_id: r.transfer_id,
        dispatch_attempt_id: r.dispatch_attempt_id,
    }
}
#[test]
fn download_fragmentation_preserves_exact_bytes_sequence_and_hash() {
    let r = request(FileDirection::Download);
    let b = binding(&r);
    let mut d = FileDecoder::new(&r).expect("decoder");
    let mut bytes = encode_frame(b, 0, FileEvent::Started).expect("frame");
    bytes.extend(
        encode_frame(
            b,
            1,
            FileEvent::Data {
                offset: 0,
                data: STANDARD.encode(b"abc"),
            },
        )
        .expect("data"),
    );
    bytes.extend(
        encode_frame(
            b,
            2,
            FileEvent::Complete {
                byte_length: 3,
                sha256: sha(b"abc"),
            },
        )
        .expect("complete"),
    );
    let mut data = Vec::new();
    for chunk in bytes.chunks(7) {
        for event in d.push(chunk).expect("fragment") {
            if let DecodedFileEvent::Data { bytes, .. } = event {
                data.extend(bytes);
            }
        }
    }
    assert_eq!(data, b"abc");
    assert!(d.finish().is_ok());
    assert!(d.push(b"{}\n").is_err());
}
#[test]
fn transfer_identity_attempt_and_frame_replay_are_never_interchangeable() {
    let r = request(FileDirection::Download);
    let mut other = binding(&r);
    other.dispatch_attempt_id = Uuid::new_v4();
    let mut d = FileDecoder::new(&r).expect("decoder");
    assert!(
        d.push(&encode_frame(other, 0, FileEvent::Started).expect("frame"))
            .is_err()
    );
    let mut d = FileDecoder::new(&r).expect("decoder");
    let frame = encode_frame(binding(&r), 0, FileEvent::Started).expect("frame");
    d.push(&frame).expect("start");
    assert!(d.push(&frame).is_err());
}
#[test]
fn upload_receipt_must_match_frozen_length_and_checksum_and_cannot_send_download_data() {
    let r = request(FileDirection::Upload);
    let b = binding(&r);
    for event in [
        FileEvent::Complete {
            byte_length: 2,
            sha256: sha(b"abc"),
        },
        FileEvent::Complete {
            byte_length: 3,
            sha256: sha(b"xyz"),
        },
        FileEvent::Data {
            offset: 0,
            data: STANDARD.encode(b"abc"),
        },
    ] {
        let mut d = FileDecoder::new(&r).expect("decoder");
        d.push(&encode_frame(b, 0, FileEvent::Started).expect("frame"))
            .expect("start");
        assert!(d.push(&encode_frame(b, 1, event).expect("frame")).is_err());
    }
}
#[test]
fn download_forged_completion_oversize_offsets_and_truncation_are_rejected() {
    let r = request(FileDirection::Download);
    let b = binding(&r);
    for event in [
        FileEvent::Data {
            offset: 1,
            data: STANDARD.encode(b"a"),
        },
        FileEvent::Data {
            offset: 0,
            data: STANDARD.encode(b"abcd"),
        },
        FileEvent::Complete {
            byte_length: 3,
            sha256: sha(b"abc"),
        },
    ] {
        let mut d = FileDecoder::new(&r).expect("decoder");
        d.push(&encode_frame(b, 0, FileEvent::Started).expect("frame"))
            .expect("start");
        assert!(d.push(&encode_frame(b, 1, event).expect("frame")).is_err());
    }
    let mut d = FileDecoder::new(&r).expect("decoder");
    d.push(b"{").expect("partial");
    assert!(d.finish().is_err());
}
#[test]
fn guest_json_is_strict_and_wire_memory_is_bounded() {
    let r = request(FileDirection::Download);
    let mut d = FileDecoder::new(&r).expect("decoder");
    assert!(d.push(&vec![b'x'; 64 * 1024 + 1]).is_err());
    let mut d = FileDecoder::new(&r).expect("decoder");
    assert!(d.push(&vec![b'x'; MAX_LINE_BYTES + 1]).is_err());
    let mut d = FileDecoder::new(&r).expect("decoder");
    let mut frame: serde_json::Value =
        serde_json::from_slice(&encode_frame(binding(&r), 0, FileEvent::Started).expect("frame"))
            .expect("json");
    frame["cloud_key"] = serde_json::json!("other/tenant/key");
    let mut bytes = serde_json::to_vec(&frame).expect("json");
    bytes.push(b'\n');
    assert!(d.push(&bytes).is_err());
}
#[test]
fn empty_files_and_fixed_error_codes_have_terminal_but_not_vm_termination_semantics() {
    let mut r = request(FileDirection::Download);
    r.byte_limit = 0;
    let b = binding(&r);
    let mut d = FileDecoder::new(&r).expect("decoder");
    d.push(&encode_frame(b, 0, FileEvent::Started).expect("frame"))
        .expect("start");
    d.push(
        &encode_frame(
            b,
            1,
            FileEvent::Complete {
                byte_length: 0,
                sha256: sha(b""),
            },
        )
        .expect("frame"),
    )
    .expect("complete");
    assert!(d.finish().is_ok());
    let mut d = FileDecoder::new(&r).expect("decoder");
    d.push(&encode_frame(b, 0, FileEvent::Started).expect("frame"))
        .expect("start");
    let events = d
        .push(
            &encode_frame(
                b,
                1,
                FileEvent::Error {
                    code: FileFailureCode::FileChanged,
                },
            )
            .expect("frame"),
        )
        .expect("error");
    assert!(matches!(
        events.as_slice(),
        [DecodedFileEvent::Error(FileFailureCode::FileChanged)]
    ));
    assert!(d.finish().is_ok());
}
