//! Fixed confidential OIDC settings and private credential files.
use crate::{
    bff_crypto::SessionKeys,
    bff_oidc::{BrowserOidc, OidcSettings},
};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    oidc: OidcSettings,
    client_secret_file: PathBuf,
    session_key_file: PathBuf,
}
pub struct BrowserConfig {
    pub oidc: BrowserOidc,
    pub keys: SessionKeys,
}
fn read(path: &Path, max: usize, private: bool) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        path.is_absolute(),
        "browser configuration paths must be absolute"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("cannot open browser configuration file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("cannot inspect browser configuration file"))?;
    anyhow::ensure!(
        metadata.is_file(),
        "browser configuration must be a regular file"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            [0o400, 0o600].contains(&(metadata.permissions().mode() & 0o777)),
            "browser credentials require 0400 or 0600 permissions"
        );
    }
    let mut data = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| anyhow::anyhow!("cannot read browser configuration file"))?;
    anyhow::ensure!(
        data.len() <= max,
        "browser configuration exceeds size limit"
    );
    Ok(data)
}
impl BrowserConfig {
    pub fn from_file(path: &Path, api_issuer: &str) -> anyhow::Result<Self> {
        let settings: Settings = serde_json::from_slice(&read(path, 32768, false)?)
            .map_err(|_| anyhow::anyhow!("invalid browser configuration"))?;
        anyhow::ensure!(
            settings.oidc.issuer == api_issuer,
            "browser and API issuer must match"
        );
        let secret = String::from_utf8(read(&settings.client_secret_file, 4096, true)?)
            .map_err(|_| anyhow::anyhow!("invalid browser client credential"))?;
        let oidc = BrowserOidc::new(
            settings.oidc,
            secret.trim_end_matches(['\r', '\n']).to_owned(),
        )?;
        let keys = SessionKeys::from_file(&settings.session_key_file)?;
        Ok(Self { oidc, keys })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    #[test]
    fn browser_secret_files_and_issuer_are_validated_without_echoing_input() {
        let directory = tempfile::tempdir().expect("private fixture directory");
        let secret = directory.path().join("secret");
        let keys = directory.path().join("keys.json");
        let settings = directory.path().join("settings.json");
        std::fs::write(&secret, "PRIVATE_BFF_SECRET_01234567890123456789\n")
            .expect("fixture secret");
        std::fs::write(&keys,serde_json::json!({"active":"a","keys":[{"id":"a","key":URL_SAFE_NO_PAD.encode([1;32])}]}).to_string()).expect("fixture keys");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [&secret, &keys] {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
                    .expect("private permission");
            }
        }
        let value = serde_json::json!({"oidc":{"issuer":"https://identity.example.test/realms/sandbox","authorization_url":"https://identity.example.test/auth","token_url":"https://identity.example.test/token","jwks_url":"https://identity.example.test/jwks","client_id":"sandbox-browser","public_origin":"https://console.example.test","scopes":["openid","sandbox:access"]},"client_secret_file":secret,"session_key_file":keys});
        std::fs::write(&settings, value.to_string()).expect("fixture settings");
        assert!(
            BrowserConfig::from_file(&settings, "https://identity.example.test/realms/sandbox")
                .is_ok()
        );
        assert!(
            BrowserConfig::from_file(&settings, "https://other-identity.example.test").is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644))
                .expect("unsafe fixture permission");
            let error =
                BrowserConfig::from_file(&settings, "https://identity.example.test/realms/sandbox")
                    .err()
                    .expect("must reject public secret");
            assert!(!error.to_string().contains("PRIVATE_BFF_SECRET"));
        }
    }
}
