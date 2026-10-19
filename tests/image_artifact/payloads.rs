//! Payload verification is tested through the real offline administrator CLI.
//! The checked-in Python stdlib fixture generator supplies all positive payload
//! hashes and byte counts; neither flate2 nor the verifier supplies an oracle.
use super::*;
use anyhow::Context;

const RAW_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const GZIP_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const LIMIT_FLAGS: [&str; 4] = [
    "--max-layer-bytes",
    "--max-total-layer-bytes",
    "--max-decoded-layer-bytes",
    "--max-total-decoded-bytes",
];
const GENEROUS: [u64; 4] = [1_048_576, 4_194_304, 1_048_576, 4_194_304];

#[derive(Clone)]
struct PayloadSpec {
    bytes: Vec<u8>,
    media_type: &'static str,
    digest: String,
    diff_id: String,
    declared_bytes: u64,
    decoded_bytes: u64,
    members: u64,
}

impl PayloadSpec {
    fn fixture(name: &str) -> anyhow::Result<Self> {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/image-payloads");
        let oracles: Vec<Value> =
            serde_json::from_slice(&fs::read(directory.join("oracles.json"))?)?;
        let expected = oracles
            .iter()
            .find(|entry| entry["file"] == name)
            .ok_or_else(|| anyhow::anyhow!("missing independent fixture oracle: {name}"))?;
        let bytes = fs::read(directory.join(name))?;
        let declared_bytes = expected["encoded_bytes"]
            .as_u64()
            .context("fixture oracle encoded byte count missing")?;
        assert_eq!(bytes.len() as u64, declared_bytes);
        Ok(Self {
            bytes,
            media_type: if name.ends_with(".tar") {
                RAW_TYPE
            } else {
                GZIP_TYPE
            },
            digest: expected["digest"]
                .as_str()
                .context("fixture oracle encoded digest missing")?
                .to_owned(),
            diff_id: expected["diff_id"]
                .as_str()
                .context("fixture oracle decoded digest missing")?
                .to_owned(),
            declared_bytes,
            decoded_bytes: expected["decoded_bytes"]
                .as_u64()
                .context("fixture oracle decoded byte count missing")?,
            members: expected["gzip_members"]
                .as_u64()
                .context("fixture oracle gzip member count missing")?,
        })
    }

    fn reidentify(&mut self) {
        // Negative tests authenticate mutated bytes without decoding them. The
        // positive decoded-stream oracle remains the independent Python value.
        self.digest = format!("sha256:{:x}", Sha256::digest(&self.bytes));
        self.declared_bytes = self.bytes.len() as u64;
    }

    fn descriptor(&self) -> Value {
        json!({"mediaType":self.media_type,"digest":self.digest,"size":self.declared_bytes})
    }

    fn identity(&self) -> Value {
        json!({"media_type":self.media_type,"digest":self.digest,
            "size_bytes":self.declared_bytes.to_string(),"diff_id":self.diff_id})
    }
}

struct PayloadLayout {
    _directory: tempfile::TempDir,
    path: PathBuf,
    root: String,
    expected_metadata: Value,
}

impl PayloadLayout {
    fn new(layers: &[PayloadSpec]) -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?;
        fs::create_dir_all(path.join("blobs/sha256"))?;
        let marker = br#"{"imageLayoutVersion":"1.0.0"}"#;
        fs::write(path.join("oci-layout"), marker)?;
        for layer in layers {
            fs::write(
                path.join("blobs/sha256").join(&layer.digest[7..]),
                &layer.bytes,
            )?;
        }
        let config = serde_json::to_vec(&json!({
            "architecture":"amd64","os":"linux",
            "rootfs":{"type":"layers","diff_ids":layers.iter().map(|layer| &layer.diff_id).collect::<Vec<_>>()}
        }))?;
        let config_digest = Self::write_blob(&path, &config)?;
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion":2,"mediaType":MANIFEST_TYPE,
            "config":{"mediaType":CONFIG_TYPE,"digest":config_digest,"size":config.len()},
            "layers":layers.iter().map(PayloadSpec::descriptor).collect::<Vec<_>>()
        }))?;
        let root = Self::write_blob(&path, &manifest)?;
        let mut unique = BTreeMap::new();
        for layer in layers {
            unique.insert(&layer.digest, layer.declared_bytes);
        }
        let expected_metadata = json!({
            "scope":"OCI_METADATA_ONLY","approval_checked":false,
            "layer_payloads_verified":false,"preparation_allowed":false,
            "platform":{"os":"linux","architecture":"amd64","variant":null},
            "root":identity(MANIFEST_TYPE,&root,&manifest.len().to_string()),"index":null,
            "selected_manifest":identity(MANIFEST_TYPE,&root,&manifest.len().to_string()),
            "config":identity(CONFIG_TYPE,&config_digest,&config.len().to_string()),
            "layers":layers.iter().map(PayloadSpec::identity).collect::<Vec<_>>(),
            "declared_layer_bytes":layers.iter().map(|layer| layer.declared_bytes).sum::<u64>().to_string(),
            "unique_declared_layer_bytes":unique.values().sum::<u64>().to_string(),
            "metadata_bytes_read":(marker.len()+config.len()+manifest.len()).to_string()
        });
        Ok(Self {
            _directory: directory,
            path,
            root,
            expected_metadata,
        })
    }

    fn write_blob(path: &Path, bytes: &[u8]) -> anyhow::Result<String> {
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        fs::write(path.join("blobs/sha256").join(&digest[7..]), bytes)?;
        Ok(digest)
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        self.path.join("blobs/sha256").join(&digest[7..])
    }

    fn invoke(&self, limits: [u64; 4]) -> anyhow::Result<Output> {
        let flags = limits.map(|value| Some(value.to_string()));
        invoke_payloads(&self.path, &self.root, &flags)
    }

    fn receipt(&self, limits: [u64; 4]) -> anyhow::Result<Value> {
        let output = self.invoke(limits)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PUBLIC_SECRET_SENTINEL"));
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    fn rejected(&self, limits: [u64; 4], code: &str) -> anyhow::Result<()> {
        let output = self.invoke(limits)?;
        assert!(!output.status.success(), "expected {code}");
        assert!(
            output.stdout.is_empty(),
            "failed verification must not emit a partial receipt"
        );
        assert_eq!(
            String::from_utf8(output.stderr)?.trim(),
            format!("Error: image payload verification failed: {code}")
        );
        Ok(())
    }

    fn expected_receipt(&self, layers: &[PayloadSpec]) -> Value {
        let mut expected = self.expected_metadata.clone();
        expected["scope"] = json!("OCI_PAYLOAD_STREAMS");
        expected["layer_payloads_verified"] = json!(true);
        expected["diff_ids_verified"] = json!(true);
        expected["archive_semantics_checked"] = json!(false);
        expected["unpack_performed"] = json!(false);
        expected["physical_storage_bound_verified"] = json!(false);
        let mut unique = BTreeMap::new();
        for layer in layers {
            unique.insert(&layer.digest, layer);
        }
        expected["encoded_bytes_read"] = json!(
            unique
                .values()
                .map(|layer| layer.declared_bytes)
                .sum::<u64>()
                .to_string()
        );
        expected["decoded_bytes_read"] = json!(
            unique
                .values()
                .map(|layer| layer.decoded_bytes)
                .sum::<u64>()
                .to_string()
        );
        expected["logical_decoded_bytes"] = json!(
            layers
                .iter()
                .map(|layer| layer.decoded_bytes)
                .sum::<u64>()
                .to_string()
        );
        expected["decoded_layer_bytes"] = json!(
            layers
                .iter()
                .map(|layer| layer.decoded_bytes.to_string())
                .collect::<Vec<_>>()
        );
        expected["unique_layers_verified"] = json!(unique.len());
        expected["gzip_members_verified"] =
            json!(unique.values().map(|layer| layer.members).sum::<u64>());
        expected
    }
}

fn invoke_payloads(
    layout: &Path,
    digest: &str,
    limits: &[Option<String>; 4],
) -> anyhow::Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbox-admin"));
    command
        .args(["image-artifact", "verify-payloads", "--layout"])
        .arg(layout)
        .args(["--expected-digest", digest, "--platform", "linux/amd64"]);
    for (flag, value) in LIMIT_FLAGS.into_iter().zip(limits) {
        if let Some(value) = value {
            command.arg(flag).arg(value);
        }
    }
    let mut child = command
        .env(
            "SANDBOX_OWNER_DATABASE_URL",
            "postgres://invalid.invalid/forbidden",
        )
        .env(
            "SANDBOX_ADMIN_DATABASE_URL",
            "postgres://invalid.invalid/forbidden",
        )
        .env("DATABASE_URL", "postgres://invalid.invalid/forbidden")
        .env("HTTP_PROXY", "http://invalid.invalid:1")
        .env("HTTPS_PROXY", "http://invalid.invalid:1")
        .env("ALL_PROXY", "http://invalid.invalid:1")
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("offline image payload CLI exceeded its fixed five-second budget");
        }
        thread::sleep(Duration::from_millis(10));
    };
    use std::io::{Read, Seek};
    let mut stdout = stdout;
    let mut stderr = stderr;
    stdout.rewind()?;
    stderr.rewind()?;
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.read_to_end(&mut output.stdout)?;
    stderr.read_to_end(&mut output.stderr)?;
    Ok(output)
}

#[test]
fn cli_verifies_raw_gzip_and_concatenated_members_without_network_database_or_writes()
-> anyhow::Result<()> {
    let layers = [
        PayloadSpec::fixture("alpha.tar")?,
        PayloadSpec::fixture("beta.tar.gz")?,
        PayloadSpec::fixture("concatenated.tar.gz")?,
    ];
    let layout = PayloadLayout::new(&layers)?;
    let before = snapshot(&layout.path)?;
    assert_eq!(layout.receipt(GENEROUS)?, layout.expected_receipt(&layers));
    assert_eq!(
        snapshot(&layout.path)?,
        before,
        "payload verification must leave every input byte unchanged"
    );
    Ok(())
}

#[test]
fn payload_command_requires_all_four_positive_and_consistent_byte_limits() -> anyhow::Result<()> {
    let layout = PayloadLayout::new(&[])?;
    for missing in 0..4 {
        let mut limits = GENEROUS.map(|value| Some(value.to_string()));
        limits[missing] = None;
        let output = invoke_payloads(&layout.path, &layout.root, &limits)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains(LIMIT_FLAGS[missing]), "{stderr}");
    }
    for zero in 0..4 {
        let mut limits = GENEROUS;
        limits[zero] = 0;
        layout.rejected(limits, "INVALID_PAYLOAD_LIMITS")?;
    }
    layout.rejected([2, 1, 1, 1], "INVALID_PAYLOAD_LIMITS")?;
    layout.rejected([1, 1, 2, 1], "INVALID_PAYLOAD_LIMITS")?;
    Ok(())
}

#[test]
fn scratch_payload_verification_reports_zero_work_and_grants_no_preparation() -> anyhow::Result<()>
{
    let layout = PayloadLayout::new(&[])?;
    assert_eq!(layout.receipt([1, 1, 1, 1])?, layout.expected_receipt(&[]));
    Ok(())
}

#[test]
fn duplicate_payloads_are_read_once_but_every_reference_consumes_logical_budgets()
-> anyhow::Result<()> {
    let layer = PayloadSpec::fixture("beta.tar.gz")?;
    let layers = [layer.clone(), layer.clone(), layer.clone()];
    let layout = PayloadLayout::new(&layers)?;
    let exact = [135, 405, 10_240, 30_720];
    assert_eq!(layout.receipt(exact)?, layout.expected_receipt(&layers));
    layout.rejected([135, 404, 10_240, 30_720], "PAYLOAD_LIMIT_EXCEEDED")?;
    layout.rejected([135, 405, 10_240, 30_719], "PAYLOAD_LIMIT_EXCEEDED")?;
    Ok(())
}

#[test]
fn encoded_and_decoded_layer_limits_accept_exact_bytes_and_reject_the_next_byte()
-> anyhow::Result<()> {
    for (name, exact) in [
        ("alpha.tar", [10_240, 10_240, 10_240, 10_240]),
        ("beta.tar.gz", [135, 135, 10_240, 10_240]),
        ("expansion.tar.gz", [356, 356, 266_240, 266_240]),
    ] {
        let layers = [PayloadSpec::fixture(name)?];
        let layout = PayloadLayout::new(&layers)?;
        assert_eq!(layout.receipt(exact)?, layout.expected_receipt(&layers));
        for field in [0, 2] {
            let mut limit = exact;
            limit[field] -= 1;
            layout.rejected(limit, "PAYLOAD_LIMIT_EXCEEDED")?;
        }
    }
    Ok(())
}

#[test]
fn actual_raw_and_gzip_blob_digest_and_size_must_match_the_authenticated_descriptor()
-> anyhow::Result<()> {
    for name in ["alpha.tar", "beta.tar.gz"] {
        let spec = PayloadSpec::fixture(name)?;
        let layout = PayloadLayout::new(std::slice::from_ref(&spec))?;
        let mut tampered = spec.bytes.clone();
        // For gzip, change mtime rather than corrupting the deflate stream.
        tampered[4] ^= 1;
        fs::write(layout.blob_path(&spec.digest), tampered)?;
        layout.rejected(GENEROUS, "DIGEST_MISMATCH")?;
        for delta in [-1_i64, 1] {
            let mut wrong_size = spec.clone();
            wrong_size.declared_bytes = (wrong_size.declared_bytes as i64 + delta) as u64;
            PayloadLayout::new(&[wrong_size])?.rejected(GENEROUS, "SIZE_MISMATCH")?;
        }
    }
    Ok(())
}

#[test]
fn gzip_diff_id_and_conflicting_duplicate_diff_ids_fail_closed() -> anyhow::Result<()> {
    let good = PayloadSpec::fixture("beta.tar.gz")?;
    let mut wrong = good.clone();
    wrong.diff_id =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    PayloadLayout::new(std::slice::from_ref(&wrong))?.rejected(GENEROUS, "DIFF_ID_MISMATCH")?;
    PayloadLayout::new(&[good, wrong])?.rejected(GENEROUS, "DIFF_ID_MISMATCH")?;
    Ok(())
}

#[test]
fn gzip_truncation_crc_isize_invalid_header_and_trailing_junk_are_not_accepted()
-> anyhow::Result<()> {
    let original = PayloadSpec::fixture("beta.tar.gz")?;
    let mut variants = Vec::new();
    for length in [1, 9, original.bytes.len() / 2, original.bytes.len() - 1] {
        variants.push(original.bytes[..length].to_vec());
    }
    for index in [0, original.bytes.len() - 8, original.bytes.len() - 4] {
        let mut bytes = original.bytes.clone();
        bytes[index] ^= 1;
        variants.push(bytes);
    }
    let mut junk = original.bytes.clone();
    junk.extend_from_slice(b"PUBLIC_SECRET_SENTINEL trailing junk");
    variants.push(junk);
    // A second incomplete member must not disappear after the first valid one.
    let mut incomplete_member = original.bytes.clone();
    incomplete_member.extend_from_slice(&original.bytes[..9]);
    variants.push(incomplete_member);
    for bytes in variants {
        let mut spec = original.clone();
        spec.bytes = bytes;
        spec.reidentify();
        PayloadLayout::new(&[spec])?.rejected(GENEROUS, "INVALID_LAYER_ENCODING")?;
    }
    Ok(())
}

#[test]
fn zstd_metadata_support_does_not_grant_payload_codec_support() -> anyhow::Result<()> {
    let mut spec = PayloadSpec::fixture("beta.tar.gz")?;
    spec.media_type = "application/vnd.oci.image.layer.v1.tar+zstd";
    let layout = PayloadLayout::new(&[spec])?;
    // The original public metadata command remains usable for this declaration.
    let metadata = verify(&layout.path, &layout.root, "linux/amd64")?;
    assert!(
        metadata.status.success(),
        "{}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&metadata.stdout)?,
        layout.expected_metadata
    );
    layout.rejected(GENEROUS, "UNSUPPORTED_PAYLOAD_MEDIA_TYPE")?;
    Ok(())
}

#[test]
fn missing_payload_is_rejected_even_though_metadata_only_verification_succeeds()
-> anyhow::Result<()> {
    let spec = PayloadSpec::fixture("beta.tar.gz")?;
    let layout = PayloadLayout::new(std::slice::from_ref(&spec))?;
    fs::remove_file(layout.blob_path(&spec.digest))?;
    let metadata = verify(&layout.path, &layout.root, "linux/amd64")?;
    assert!(metadata.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&metadata.stdout)?,
        layout.expected_metadata
    );
    layout.rejected(GENEROUS, "METADATA_UNAVAILABLE")?;
    Ok(())
}

#[test]
fn gzip_header_bytes_are_bounded_and_more_than_1024_empty_members_fail_closed() -> anyhow::Result<()>
{
    let header = PayloadSpec::fixture("long-header.tar.gz")?;
    let layout = PayloadLayout::new(std::slice::from_ref(&header))?;
    layout.rejected([262_279, 262_280, 10_240, 10_240], "PAYLOAD_LIMIT_EXCEEDED")?;
    // A legal RFC gzip FNAME can still exceed the decoder's fixed header
    // allocation ceiling; accepting the encoding is never an unbounded read.
    layout.rejected([262_280, 262_280, 10_240, 10_240], "INVALID_LAYER_ENCODING")?;
    let mut unterminated_header = PayloadSpec::fixture("long-header.tar.gz")?;
    unterminated_header.bytes.truncate(10 + 256 * 1024);
    unterminated_header.reidentify();
    PayloadLayout::new(&[unterminated_header])?.rejected(GENEROUS, "INVALID_LAYER_ENCODING")?;
    let exact = [PayloadSpec::fixture("exact-empty-members.gz")?];
    let exact_layout = PayloadLayout::new(&exact)?;
    assert_eq!(
        exact_layout.receipt(GENEROUS)?,
        exact_layout.expected_receipt(&exact)
    );
    let members = PayloadSpec::fixture("empty-members.gz")?;
    PayloadLayout::new(&[members])?.rejected(GENEROUS, "PAYLOAD_LIMIT_EXCEEDED")?;
    let separate_layers = [
        PayloadSpec::fixture("split-empty-members-a.gz")?,
        PayloadSpec::fixture("split-empty-members-b.gz")?,
    ];
    PayloadLayout::new(&separate_layers)?.rejected(GENEROUS, "PAYLOAD_LIMIT_EXCEEDED")?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_fifo_and_directory_payloads_fail_without_following_or_waiting_and_without_leaks()
-> anyhow::Result<()> {
    use std::os::unix::fs::symlink;
    let spec = PayloadSpec::fixture("alpha.tar")?;
    let layout = PayloadLayout::new(std::slice::from_ref(&spec))?;
    let outside = tempfile::tempdir()?;
    let secret = outside
        .path()
        .join("PRIVATE_REPOSITORY_PUBLIC_SECRET_SENTINEL");
    fs::write(&secret, &spec.bytes)?;
    let blob = layout.blob_path(&spec.digest);
    fs::remove_file(&blob)?;
    symlink(&secret, &blob)?;
    layout.rejected(GENEROUS, "METADATA_UNAVAILABLE")?;
    fs::remove_file(&blob)?;
    nix::unistd::mkfifo(
        &blob,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    layout.rejected(GENEROUS, "METADATA_UNAVAILABLE")?;
    fs::remove_file(&blob)?;
    fs::create_dir(&blob)?;
    layout.rejected(GENEROUS, "METADATA_UNAVAILABLE")?;
    assert_eq!(fs::read(secret)?, spec.bytes);
    Ok(())
}
