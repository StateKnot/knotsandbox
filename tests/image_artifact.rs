//! Offline OCI verification is exercised through the actual administrator CLI.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// These independent SHA-256 and byte-count oracles were calculated from the
// checked-in bytes with Python hashlib, not the implementation under test.
const ROOT: &str = "sha256:bbcc60ed9423dd84b19a56d09759aec31ee3db1b729455f9414646808b624379";
const AMD_MANIFEST: &str =
    "sha256:0a14e0296c0ab0d00e9b8c9053f9cab062c5848a9e763ecd3bb5288dcb8fbb57";
const AMD_CONFIG: &str = "sha256:7bfed7d6080f5d9aa427991b771a274ee4845f93232f914a49afbe3f895a141c";
const ARM_MANIFEST: &str =
    "sha256:99662d44a999ecc83060817f9abdbbe10fca3322c27d543f6171ef3b9581f5d7";
const ARM_CONFIG: &str = "sha256:fdba5256818185b1fbbca0f0237eb6230592011a42bf19e5575d56059b56e4fd";
const LAYER: &str = "sha256:5b048e9bfb6a84322993b9986a2f5722da4e45f653e25363f5c5cff03de21f72";
const DIFF: &str = "sha256:ec7e3831d613c86b6b14c1284c8df691ddfeac02b2b1b8e9328b36c85c1af7a9";
const INDEX_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/image-artifact")
}

fn snapshot(directory: &Path) -> anyhow::Result<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> anyhow::Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                visit(root, &path, files)?;
            } else {
                files.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(directory, directory, &mut files)?;
    Ok(files)
}

fn verify(layout: &Path, digest: &str, platform: &str) -> anyhow::Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sandbox-admin"))
        .args(["image-artifact", "verify", "--layout"])
        .arg(layout)
        .args(["--expected-digest", digest, "--platform", platform])
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
            anyhow::bail!("offline image metadata CLI exceeded its fixed five-second budget");
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

fn identity(media_type: &str, digest: &str, size: &str) -> Value {
    json!({"media_type":media_type,"digest":digest,"size_bytes":size})
}

struct Layout {
    _directory: tempfile::TempDir,
    resolved: PathBuf,
}

impl Layout {
    fn copy() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        for (name, bytes) in snapshot(&fixture())? {
            let destination = directory.path().join(name);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(destination, bytes)?;
        }
        let resolved = directory.path().canonicalize()?;
        Ok(Self {
            _directory: directory,
            resolved,
        })
    }

    fn path(&self) -> &Path {
        &self.resolved
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        self.path().join("blobs/sha256").join(&digest[7..])
    }

    fn read(&self, digest: &str) -> anyhow::Result<Value> {
        Ok(serde_json::from_slice(&fs::read(self.blob_path(digest))?)?)
    }

    fn write_bytes(&self, bytes: &[u8]) -> anyhow::Result<String> {
        // Mutations need new roots; the positive receipt uses fixed oracles.
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        fs::write(self.blob_path(&digest), bytes)?;
        Ok(digest)
    }

    fn write(&self, document: &Value) -> anyhow::Result<String> {
        self.write_bytes(&serde_json::to_vec(document)?)
    }

    fn replace_config(&self, manifest: &mut Value, config: &Value) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(config)?;
        manifest["config"]["digest"] = json!(self.write_bytes(&bytes)?);
        manifest["config"]["size"] = json!(bytes.len());
        Ok(())
    }

    fn rejected(&self, digest: &str, platform: &str, code: &str) -> anyhow::Result<()> {
        let output = verify(self.path(), digest, platform)?;
        assert!(!output.status.success(), "expected {code}");
        assert!(
            output.stdout.is_empty(),
            "failed verification must not emit a partial receipt"
        );
        assert_eq!(
            String::from_utf8(output.stderr)?.trim(),
            format!("Error: image artifact metadata verification failed: {code}")
        );
        Ok(())
    }
}

#[test]
fn cli_verifies_the_selected_platform_without_layers_network_or_database() -> anyhow::Result<()> {
    let layout = fixture();
    let before = snapshot(&layout)?;
    let output = verify(&layout, ROOT, "linux/amd64")?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PUBLIC_SECRET_SENTINEL"));
    let mut layer = identity(LAYER_TYPE, LAYER, "31");
    layer["diff_id"] = json!(DIFF);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        json!({
            "scope":"OCI_METADATA_ONLY",
            "approval_checked":false,
            "layer_payloads_verified":false,
            "preparation_allowed":false,
            "platform":{"os":"linux","architecture":"amd64","variant":null},
            "root":identity(INDEX_TYPE,ROOT,"507"),
            "index":identity(INDEX_TYPE,ROOT,"507"),
            "selected_manifest":identity(MANIFEST_TYPE,AMD_MANIFEST,"554"),
            "config":identity(CONFIG_TYPE,AMD_CONFIG,"362"),
            "layers":[layer.clone(),layer],
            "declared_layer_bytes":"62",
            "unique_declared_layer_bytes":"31",
            "metadata_bytes_read":"1454"
        })
    );
    assert_eq!(
        snapshot(&layout)?,
        before,
        "verification must not alter the OCI layout"
    );
    assert!(!layout.join("blobs/sha256").join(&LAYER[7..]).exists());
    Ok(())
}

#[test]
fn exact_arm_variant_selects_scratch_and_direct_manifest_needs_no_index() -> anyhow::Result<()> {
    let layout = Layout::copy()?;
    let selected = verify(layout.path(), ROOT, "linux/arm64/v8")?;
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let receipt: Value = serde_json::from_slice(&selected.stdout)?;
    assert_eq!(
        receipt,
        json!({
            "scope":"OCI_METADATA_ONLY","approval_checked":false,
            "layer_payloads_verified":false,"preparation_allowed":false,
            "platform":{"os":"linux","architecture":"arm64","variant":"v8"},
            "root":identity(INDEX_TYPE,ROOT,"507"),"index":identity(INDEX_TYPE,ROOT,"507"),
            "selected_manifest":identity(MANIFEST_TYPE,ARM_MANIFEST,"249"),
            "config":identity(CONFIG_TYPE,ARM_CONFIG,"106"),"layers":[],
            "declared_layer_bytes":"0","unique_declared_layer_bytes":"0",
            "metadata_bytes_read":"893"
        })
    );
    fs::remove_file(layout.path().join("index.json"))?;
    let direct = verify(layout.path(), ARM_MANIFEST, "linux/arm64/v8")?;
    assert!(
        direct.status.success(),
        "{}",
        String::from_utf8_lossy(&direct.stderr)
    );
    let mut expected = receipt;
    expected["root"] = identity(MANIFEST_TYPE, ARM_MANIFEST, "249");
    expected["index"] = Value::Null;
    expected["metadata_bytes_read"] = json!("386");
    assert_eq!(serde_json::from_slice::<Value>(&direct.stdout)?, expected);
    layout.rejected(ROOT, "linux/arm64", "PLATFORM_MISMATCH")?;
    layout.rejected(ARM_MANIFEST, "linux/arm64", "PLATFORM_MISMATCH")?;
    Ok(())
}

#[test]
fn invalid_input_identifiers_do_not_become_paths_or_network_requests() -> anyhow::Result<()> {
    let layout = Layout::copy()?;
    for digest in [
        "sha256:ABCD",
        "sha512:abc",
        "sha256:../../outside",
        "",
        &ROOT.to_uppercase(),
    ] {
        layout.rejected(digest, "linux/amd64", "INVALID_DIGEST")?;
    }
    for platform in [
        "windows/amd64",
        "linux/riscv64",
        "linux/amd64/",
        "linux/arm64/v8/extra",
        "linux/arm64/V8",
        "linux/arm64/☃",
    ] {
        layout.rejected(ROOT, platform, "UNSUPPORTED_PLATFORM")?;
    }
    Ok(())
}

#[test]
fn authenticated_metadata_bytes_and_declared_sizes_must_both_match() -> anyhow::Result<()> {
    let layout = Layout::copy()?;
    let mut bytes = fs::read(layout.blob_path(AMD_CONFIG))?;
    bytes[1] = b' ';
    fs::write(layout.blob_path(AMD_CONFIG), bytes)?;
    layout.rejected(ROOT, "linux/amd64", "DIGEST_MISMATCH")?;

    let layout = Layout::copy()?;
    let mut index = layout.read(ROOT)?;
    index["manifests"][0]["size"] = json!(555);
    let digest = layout.write(&index)?;
    layout.rejected(&digest, "linux/amd64", "SIZE_MISMATCH")?;

    let mut manifest = layout.read(AMD_MANIFEST)?;
    manifest["config"]["size"] = json!(361);
    let digest = layout.write(&manifest)?;
    layout.rejected(&digest, "linux/amd64", "SIZE_MISMATCH")?;
    Ok(())
}

#[test]
fn index_selection_is_exact_and_rejects_ambiguity_nested_indexes_and_conflicts()
-> anyhow::Result<()> {
    let layout = Layout::copy()?;
    let original = layout.read(ROOT)?;
    let mut ambiguous = original.clone();
    let duplicate = ambiguous["manifests"][0].clone();
    ambiguous["manifests"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture array is missing"))?
        .push(duplicate);
    layout.rejected(
        &layout.write(&ambiguous)?,
        "linux/amd64",
        "AMBIGUOUS_PLATFORM",
    )?;

    let mut nested = original.clone();
    nested["manifests"][1]["mediaType"] = json!(INDEX_TYPE);
    layout.rejected(
        &layout.write(&nested)?,
        "linux/amd64",
        "UNSUPPORTED_MEDIA_TYPE",
    )?;

    let mut conflict = original.clone();
    let mut entry = conflict["manifests"][0].clone();
    entry["size"] = json!(555);
    conflict["manifests"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture array is missing"))?
        .push(entry);
    layout.rejected(
        &layout.write(&conflict)?,
        "linux/amd64",
        "DESCRIPTOR_CONFLICT",
    )?;

    let mut unknown = original;
    let unknown_entries = unknown["manifests"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture array is missing"))?;
    unknown_entries.extend([
        json!({
            "mediaType":"application/example.unknown", "digest":LAYER, "size":31,
            "platform":{"architecture":"amd64","os":"linux"}
        }),
        json!({
            "mediaType":"application/example.unknown", "digest":format!("sha512:{}", "a".repeat(128)), "size":31
        }),
        json!({
            "mediaType":"application/example.unknown", "digest":AMD_MANIFEST, "size":555,
            "platform":{"architecture":"amd64","os":"linux"}
        }),
    ]);
    let output = verify(layout.path(), &layout.write(&unknown)?, "linux/amd64")?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !layout.blob_path(LAYER).exists(),
        "unknown entry must not need a payload"
    );
    Ok(())
}

#[test]
fn manifest_config_platform_and_variant_cannot_override_the_selected_platform() -> anyhow::Result<()>
{
    let layout = Layout::copy()?;
    for (field, replacement) in [
        ("architecture", json!("arm64")),
        ("os", json!("windows")),
        ("variant", json!("v8")),
    ] {
        let mut manifest = layout.read(AMD_MANIFEST)?;
        let mut config = layout.read(AMD_CONFIG)?;
        config[field] = replacement;
        layout.replace_config(&mut manifest, &config)?;
        layout.rejected(
            &layout.write(&manifest)?,
            "linux/amd64",
            "PLATFORM_MISMATCH",
        )?;
    }
    let mut index = layout.read(ROOT)?;
    index["manifests"][1]["platform"]
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture object is missing"))?
        .remove("variant");
    layout.rejected(&layout.write(&index)?, "linux/arm64", "PLATFORM_MISMATCH")?;
    Ok(())
}

#[test]
fn untrusted_json_rejects_duplicate_keys_even_in_opaque_extension_fields() -> anyhow::Result<()> {
    let layout = Layout::copy()?;
    let original = fs::read_to_string(layout.blob_path(ROOT))?;
    for extension in [
        r#""schemaVersion":2,"schemaVersion":2,"#,
        r#""extension":{"secret":1,"secret":2},"#,
    ] {
        let raw = format!("{{{extension}{}", &original[1..]);
        layout.rejected(
            &layout.write_bytes(raw.as_bytes())?,
            "linux/amd64",
            "INVALID_METADATA",
        )?;
    }
    let mut manifest = layout.read(AMD_MANIFEST)?;
    let raw = br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"extension":{"token":"private","token":"private"}}"#;
    manifest["config"]["digest"] = json!(layout.write_bytes(raw)?);
    manifest["config"]["size"] = json!(raw.len());
    layout.rejected(&layout.write(&manifest)?, "linux/amd64", "INVALID_METADATA")?;
    Ok(())
}

#[test]
fn unsupported_content_never_grants_a_preparation_receipt() -> anyhow::Result<()> {
    let layout = Layout::copy()?;
    for (key, value) in [
        ("data", json!("inline-secret")),
        ("urls", json!(["https://invalid.invalid/layer"])),
        ("artifactType", json!("application/example.artifact")),
        ("subject", json!({"digest":LAYER})),
    ] {
        let mut manifest = layout.read(AMD_MANIFEST)?;
        manifest["layers"][0][key] = value.clone();
        layout.rejected(
            &layout.write(&manifest)?,
            "linux/amd64",
            "UNSUPPORTED_DESCRIPTOR",
        )?;
        let mut manifest = layout.read(AMD_MANIFEST)?;
        manifest[key] = value;
        layout.rejected(
            &layout.write(&manifest)?,
            "linux/amd64",
            "UNSUPPORTED_DESCRIPTOR",
        )?;
    }
    let mut manifest = layout.read(AMD_MANIFEST)?;
    manifest["layers"][0]["mediaType"] =
        json!("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip");
    layout.rejected(
        &layout.write(&manifest)?,
        "linux/amd64",
        "UNSUPPORTED_MEDIA_TYPE",
    )?;
    let mut manifest = layout.read(AMD_MANIFEST)?;
    manifest["layers"][1]["size"] = json!(32);
    layout.rejected(
        &layout.write(&manifest)?,
        "linux/amd64",
        "DESCRIPTOR_CONFLICT",
    )?;
    let mut manifest = layout.read(AMD_MANIFEST)?;
    let mut config = layout.read(AMD_CONFIG)?;
    config["rootfs"]["diff_ids"] = json!([DIFF]);
    layout.replace_config(&mut manifest, &config)?;
    layout.rejected(&layout.write(&manifest)?, "linux/amd64", "INVALID_METADATA")?;
    Ok(())
}

#[test]
fn uncompressed_layer_declarations_must_agree_without_claiming_payload_verification()
-> anyhow::Result<()> {
    let layout = Layout::copy()?;
    let mut manifest = layout.read(AMD_MANIFEST)?;
    for layer in manifest["layers"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture array is missing"))?
    {
        layer["mediaType"] = json!("application/vnd.oci.image.layer.v1.tar");
    }
    layout.rejected(&layout.write(&manifest)?, "linux/amd64", "INVALID_METADATA")?;

    let mut config = layout.read(AMD_CONFIG)?;
    config["rootfs"]["diff_ids"] = json!([LAYER, LAYER]);
    layout.replace_config(&mut manifest, &config)?;
    let output = verify(layout.path(), &layout.write(&manifest)?, "linux/amd64")?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["layer_payloads_verified"], false);
    assert_eq!(receipt["preparation_allowed"], false);
    assert_eq!(receipt["layers"][0]["diff_id"], LAYER);
    assert!(!layout.blob_path(LAYER).exists());

    let mut compressed = layout.read(AMD_MANIFEST)?;
    for layer in compressed["layers"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture array is missing"))?
    {
        layer["mediaType"] = json!("application/vnd.oci.image.layer.v1.tar+zstd");
    }
    let output = verify(layout.path(), &layout.write(&compressed)?, "linux/amd64")?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["layers"][0]["diff_id"], DIFF);
    assert_eq!(receipt["layer_payloads_verified"], false);
    Ok(())
}

#[test]
fn metadata_and_descriptor_budgets_fail_closed_without_allocating_layer_payloads()
-> anyhow::Result<()> {
    let layout = Layout::copy()?;
    let original = layout.read(ROOT)?;
    let mut many = original.clone();
    many["manifests"] = json!(vec![original["manifests"][1].clone(); 129]);
    layout.rejected(
        &layout.write(&many)?,
        "linux/amd64",
        "METADATA_LIMIT_EXCEEDED",
    )?;

    let mut manifest = layout.read(AMD_MANIFEST)?;
    manifest["layers"] = json!(vec![manifest["layers"][0].clone(); 257]);
    layout.rejected(
        &layout.write(&manifest)?,
        "linux/amd64",
        "METADATA_LIMIT_EXCEEDED",
    )?;

    let mut manifest = layout.read(AMD_MANIFEST)?;
    manifest["layers"][0]["size"] = json!(1_u64 << 63);
    layout.rejected(&layout.write(&manifest)?, "linux/amd64", "INVALID_METADATA")?;

    let mut manifest = layout.read(AMD_MANIFEST)?;
    let mut layer = manifest["layers"][0].clone();
    layer["size"] = json!(i64::MAX);
    manifest["layers"] = json!([layer.clone(), layer.clone(), layer]);
    let mut config = layout.read(AMD_CONFIG)?;
    config["rootfs"]["diff_ids"] = json!([DIFF, DIFF, DIFF]);
    layout.replace_config(&mut manifest, &config)?;
    layout.rejected(&layout.write(&manifest)?, "linux/amd64", "INTEGER_OVERFLOW")?;

    for target in [ROOT, AMD_MANIFEST, AMD_CONFIG] {
        let mut bytes = fs::read(layout.blob_path(target))?;
        bytes.resize(1024 * 1024 + 1, b' ');
        let oversized = layout.write_bytes(&bytes)?;
        if target == ROOT {
            layout.rejected(&oversized, "linux/amd64", "METADATA_LIMIT_EXCEEDED")?;
        } else if target == AMD_MANIFEST {
            let mut index = layout.read(ROOT)?;
            index["manifests"][0]["digest"] = json!(oversized);
            index["manifests"][0]["size"] = json!(bytes.len());
            layout.rejected(
                &layout.write(&index)?,
                "linux/amd64",
                "METADATA_LIMIT_EXCEEDED",
            )?;
        } else {
            let mut manifest = layout.read(AMD_MANIFEST)?;
            manifest["config"]["digest"] = json!(oversized);
            manifest["config"]["size"] = json!(bytes.len());
            layout.rejected(
                &layout.write(&manifest)?,
                "linux/amd64",
                "METADATA_LIMIT_EXCEEDED",
            )?;
        }
    }
    // All three blobs independently fit 1 MiB, but including the layout marker
    // makes the entire closure exceed its separate 3 MiB budget.
    let mut config_bytes = serde_json::to_vec(&layout.read(AMD_CONFIG)?)?;
    config_bytes.resize(1024 * 1024, b' ');
    let config_digest = layout.write_bytes(&config_bytes)?;
    let mut manifest = layout.read(AMD_MANIFEST)?;
    manifest["config"]["digest"] = json!(config_digest);
    manifest["config"]["size"] = json!(config_bytes.len());
    let mut manifest_bytes = serde_json::to_vec(&manifest)?;
    manifest_bytes.resize(1024 * 1024, b' ');
    let manifest_digest = layout.write_bytes(&manifest_bytes)?;
    let mut index = layout.read(ROOT)?;
    index["manifests"][0]["digest"] = json!(manifest_digest);
    index["manifests"][0]["size"] = json!(manifest_bytes.len());
    let mut index_bytes = serde_json::to_vec(&index)?;
    index_bytes.resize(1024 * 1024, b' ');
    layout.rejected(
        &layout.write_bytes(&index_bytes)?,
        "linux/amd64",
        "METADATA_LIMIT_EXCEEDED",
    )?;
    fs::write(layout.path().join("oci-layout"), vec![b' '; 4097])?;
    layout.rejected(ROOT, "linux/amd64", "METADATA_LIMIT_EXCEEDED")?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinks_and_fifos_are_rejected_without_following_or_waiting_for_a_writer() -> anyhow::Result<()>
{
    use std::os::unix::fs::symlink;
    let layout = Layout::copy()?;
    let parent = tempfile::tempdir()?;
    let alias = parent.path().join("layout");
    symlink(layout.path(), &alias)?;
    let result = verify(&alias, ROOT, "linux/amd64")?;
    assert!(!result.status.success());
    assert!(String::from_utf8(result.stderr)?.contains("METADATA_UNAVAILABLE"));

    let outside = parent.path().join("config");
    fs::write(&outside, fs::read(layout.blob_path(AMD_CONFIG))?)?;
    fs::remove_file(layout.blob_path(AMD_CONFIG))?;
    symlink(&outside, layout.blob_path(AMD_CONFIG))?;
    layout.rejected(ROOT, "linux/amd64", "METADATA_UNAVAILABLE")?;
    fs::remove_file(layout.blob_path(AMD_CONFIG))?;
    nix::unistd::mkfifo(
        &layout.blob_path(AMD_CONFIG),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    layout.rejected(ROOT, "linux/amd64", "METADATA_UNAVAILABLE")?;
    fs::remove_file(layout.path().join("oci-layout"))?;
    nix::unistd::mkfifo(
        &layout.path().join("oci-layout"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    layout.rejected(ROOT, "linux/amd64", "METADATA_UNAVAILABLE")?;
    Ok(())
}

#[path = "image_artifact/payloads.rs"]
mod payloads;
