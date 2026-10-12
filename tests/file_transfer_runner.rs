#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used)]
#[allow(dead_code, unused_imports)]
#[path = "../src/file_transfer_path.rs"]
mod path;
#[allow(dead_code)]
#[path = "../src/file_transfer_protocol.rs"]
mod protocol;
#[allow(dead_code)]
#[path = "../src/file_transfer_runner.rs"]
mod runner;
use path::RelativeFilePath;
use protocol::{
    DecodedFileEvent, FileBinding, FileDecoder, FileDirection, FileFailureCode, FileRequest,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
fn request(direction: FileDirection, bytes: &[u8]) -> FileRequest {
    FileRequest {
        protocol_version: 1,
        transfer_id: Uuid::new_v4(),
        dispatch_attempt_id: Uuid::new_v4(),
        direction,
        path: RelativeFilePath::new("file.bin".into()).unwrap(),
        byte_limit: bytes.len() as u64,
        expected_length: if direction == FileDirection::Upload {
            Some(bytes.len() as u64)
        } else {
            None
        },
        expected_sha256: if direction == FileDirection::Upload {
            Some(hex::encode(Sha256::digest(bytes)))
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
fn wire(r: &FileRequest, body: &[u8]) -> Vec<u8> {
    let mut out = serde_json::to_vec(r).unwrap();
    out.push(b'\n');
    out.extend_from_slice(body);
    out
}
#[test]
fn real_linux_helper_roundtrip_streams_binary_file_without_shell_or_cloud() {
    let root = tempfile::tempdir().unwrap();
    let bytes: Vec<_> = (0..20000).map(|i| (i % 256) as u8).collect();
    let upload = request(FileDirection::Upload, &bytes);
    let mut output = vec![];
    runner::run_file_transfer(
        &mut std::io::Cursor::new(wire(&upload, &bytes)),
        &mut output,
        root.path(),
        binding(&upload),
    )
    .unwrap();
    let mut decoder = FileDecoder::new(&upload).unwrap();
    let frames = decoder.push(&output).unwrap();
    decoder.finish().unwrap();
    assert!(matches!(
        &frames[1],
        DecodedFileEvent::Complete {
            byte_length: 20000,
            ..
        }
    ));
    assert_eq!(std::fs::read(root.path().join("file.bin")).unwrap(), bytes);
    let download = request(FileDirection::Download, &bytes);
    let mut output = vec![];
    runner::run_file_transfer(
        &mut std::io::Cursor::new(wire(&download, &[])),
        &mut output,
        root.path(),
        binding(&download),
    )
    .unwrap();
    let mut decoder = FileDecoder::new(&download).unwrap();
    let mut observed = vec![];
    for chunk in output.chunks(16 * 1024) {
        for frame in decoder.push(chunk).unwrap() {
            if let DecodedFileEvent::Data { bytes, .. } = frame {
                observed.extend(bytes);
            }
        }
    }
    decoder.finish().unwrap();
    assert_eq!(observed, bytes);
}
#[test]
fn exact_hundred_mib_download_stays_within_frame_budget_with_bounded_memory() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let block = vec![b'x'; 1024 * 1024];
    let mut file = std::fs::File::create(root.path().join("file.bin")).unwrap();
    let mut hash = Sha256::new();
    for _ in 0..100 {
        file.write_all(&block).unwrap();
        hash.update(&block);
    }
    file.sync_all().unwrap();
    drop(file);
    let mut r = request(FileDirection::Download, &[]);
    r.byte_limit = path::MAX_FILE_BYTES;
    struct VerifiedOutput {
        decoder: FileDecoder,
        received: u64,
        terminal: Option<(u64, String)>,
    }
    impl Write for VerifiedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            for frame in self.decoder.push(bytes).map_err(std::io::Error::other)? {
                match frame {
                    DecodedFileEvent::Data { bytes, .. } => self.received += bytes.len() as u64,
                    DecodedFileEvent::Complete {
                        byte_length,
                        sha256,
                    } => self.terminal = Some((byte_length, sha256)),
                    DecodedFileEvent::Error(_) => {
                        panic!("maximum authorized regular file must download")
                    }
                    DecodedFileEvent::Started => {}
                }
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = VerifiedOutput {
        decoder: FileDecoder::new(&r).unwrap(),
        received: 0,
        terminal: None,
    };
    runner::run_file_transfer(
        &mut std::io::Cursor::new(wire(&r, &[])),
        &mut output,
        root.path(),
        binding(&r),
    )
    .unwrap();
    output.decoder.finish().unwrap();
    assert_eq!(output.received, path::MAX_FILE_BYTES);
    assert_eq!(
        output.terminal,
        Some((path::MAX_FILE_BYTES, hex::encode(hash.finalize())))
    );
}

#[test]
fn existing_target_and_symlink_fail_without_overwriting_file() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.bin"), b"old").unwrap();
    let r = request(FileDirection::Upload, b"new");
    let mut output = vec![];
    runner::run_file_transfer(
        &mut std::io::Cursor::new(wire(&r, b"new")),
        &mut output,
        root.path(),
        binding(&r),
    )
    .unwrap();
    let mut d = FileDecoder::new(&r).unwrap();
    let frames = d.push(&output).unwrap();
    d.finish().unwrap();
    assert!(matches!(
        frames[1],
        DecodedFileEvent::Error(FileFailureCode::TargetExists)
    ));
    assert_eq!(std::fs::read(root.path().join("file.bin")).unwrap(), b"old");
    std::fs::remove_file(root.path().join("file.bin")).unwrap();
    symlink("/etc/passwd", root.path().join("file.bin")).unwrap();
    let mut output = vec![];
    runner::run_file_transfer(
        &mut std::io::Cursor::new(wire(&r, b"new")),
        &mut output,
        root.path(),
        binding(&r),
    )
    .unwrap();
    let mut d = FileDecoder::new(&r).unwrap();
    assert!(matches!(
        d.push(&output).unwrap()[1],
        DecodedFileEvent::Error(FileFailureCode::NotRegular)
    ));
    d.finish().unwrap();
}
#[test]
fn oversized_or_mismatched_header_never_opens_workspace_and_download_has_no_body() {
    let root = tempfile::tempdir().unwrap();
    let r = request(FileDirection::Download, b"abc");
    let mut output = vec![];
    let mut wrong = binding(&r);
    wrong.dispatch_attempt_id = Uuid::new_v4();
    assert!(
        runner::run_file_transfer(
            &mut std::io::Cursor::new(wire(&r, &[])),
            &mut output,
            root.path(),
            wrong
        )
        .is_err()
    );
    assert!(output.is_empty());
    assert!(
        runner::run_file_transfer(
            &mut std::io::Cursor::new(vec![b'x'; 16 * 1024 + 1]),
            &mut output,
            root.path(),
            binding(&r)
        )
        .is_err()
    );
    assert!(output.is_empty());
    runner::run_file_transfer(
        &mut std::io::Cursor::new(wire(&r, b"forbidden")),
        &mut output,
        root.path(),
        binding(&r),
    )
    .unwrap();
    let mut d = FileDecoder::new(&r).unwrap();
    assert!(matches!(
        d.push(&output).unwrap()[1],
        DecodedFileEvent::Error(FileFailureCode::IoFailed)
    ));
    d.finish().unwrap();
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
}
