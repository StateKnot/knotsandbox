//! Server-side browser-session encryption. Cookies contain only random opaque
//! identifiers; every ciphertext is bound to one record, purpose and DR epoch.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use std::{collections::BTreeMap, io::Read, path::Path};
use uuid::Uuid;

const MAX_PLAINTEXT: usize = 65536;
const MAX_KEY_FILE: usize = 8192;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionCryptoError {
    #[error("invalid browser-session encryption key configuration")]
    Configuration,
    #[error("browser-session encryption failed")]
    Encrypt,
    #[error("browser-session ciphertext rejected")]
    Decrypt,
    #[error("secure random source unavailable")]
    Random,
}
#[derive(Clone, Copy)]
pub enum Purpose {
    Login,
    Session,
}
impl Purpose {
    fn byte(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::Session => 2,
        }
    }
}

// Neither key material nor decrypted bearer values implement Debug/Serialize.
pub struct SessionKeys {
    active: String,
    keys: BTreeMap<String, aead::LessSafeKey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    active: String,
    keys: Vec<KeyEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    id: String,
    key: String,
}
impl SessionKeys {
    pub fn from_file(path: &Path) -> Result<Self, SessionCryptoError> {
        if !path.is_absolute() {
            return Err(SessionCryptoError::Configuration);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
        }
        let file = options
            .open(path)
            .map_err(|_| SessionCryptoError::Configuration)?;
        let metadata = file
            .metadata()
            .map_err(|_| SessionCryptoError::Configuration)?;
        if !metadata.is_file() {
            return Err(SessionCryptoError::Configuration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if ![0o400, 0o600].contains(&(metadata.permissions().mode() & 0o777)) {
                return Err(SessionCryptoError::Configuration);
            }
        }
        let mut bytes = Vec::new();
        file.take(MAX_KEY_FILE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SessionCryptoError::Configuration)?;
        Self::parse(&bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self, SessionCryptoError> {
        if bytes.is_empty() || bytes.len() > MAX_KEY_FILE {
            return Err(SessionCryptoError::Configuration);
        }
        let input: KeyFile =
            serde_json::from_slice(bytes).map_err(|_| SessionCryptoError::Configuration)?;
        if input.keys.is_empty() || input.keys.len() > 8 {
            return Err(SessionCryptoError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for entry in input.keys {
            if entry.id.is_empty()
                || entry.id.len() > 32
                || !entry
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err(SessionCryptoError::Configuration);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(&entry.key)
                .map_err(|_| SessionCryptoError::Configuration)?;
            if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != entry.key {
                return Err(SessionCryptoError::Configuration);
            }
            let key = aead::UnboundKey::new(&aead::AES_256_GCM, &bytes)
                .map_err(|_| SessionCryptoError::Configuration)?;
            if keys.insert(entry.id, aead::LessSafeKey::new(key)).is_some() {
                return Err(SessionCryptoError::Configuration);
            }
        }
        if !keys.contains_key(&input.active) {
            return Err(SessionCryptoError::Configuration);
        }
        Ok(Self {
            active: input.active,
            keys,
        })
    }
    pub fn encrypt(
        &self,
        purpose: Purpose,
        id: Uuid,
        epoch: Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SessionCryptoError> {
        if plaintext.len() > MAX_PLAINTEXT || id.is_nil() || epoch.is_nil() {
            return Err(SessionCryptoError::Encrypt);
        }
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SessionCryptoError::Random)?;
        let key = self
            .keys
            .get(&self.active)
            .ok_or(SessionCryptoError::Configuration)?;
        let mut body = plaintext.to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(binding(purpose, id, epoch)),
            &mut body,
        )
        .map_err(|_| SessionCryptoError::Encrypt)?;
        let mut frame = Vec::with_capacity(2 + self.active.len() + nonce.len() + body.len());
        frame.extend([1, self.active.len() as u8]);
        frame.extend(self.active.as_bytes());
        frame.extend(nonce);
        frame.extend(body);
        Ok(frame)
    }
    pub fn decrypt(
        &self,
        purpose: Purpose,
        id: Uuid,
        epoch: Uuid,
        frame: &[u8],
    ) -> Result<Vec<u8>, SessionCryptoError> {
        if frame.len() < 31
            || frame.len() > MAX_PLAINTEXT + 62
            || frame[0] != 1
            || id.is_nil()
            || epoch.is_nil()
        {
            return Err(SessionCryptoError::Decrypt);
        }
        let key_length = frame[1] as usize;
        if !(1..=32).contains(&key_length) || frame.len() < 2 + key_length + 12 + 16 {
            return Err(SessionCryptoError::Decrypt);
        }
        let key_id = std::str::from_utf8(&frame[2..2 + key_length])
            .map_err(|_| SessionCryptoError::Decrypt)?;
        let key = self.keys.get(key_id).ok_or(SessionCryptoError::Decrypt)?;
        let nonce: [u8; 12] = frame[2 + key_length..14 + key_length]
            .try_into()
            .map_err(|_| SessionCryptoError::Decrypt)?;
        let mut body = frame[14 + key_length..].to_vec();
        let decrypted = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(binding(purpose, id, epoch)),
                &mut body,
            )
            .map_err(|_| SessionCryptoError::Decrypt)?;
        if decrypted.len() > MAX_PLAINTEXT {
            return Err(SessionCryptoError::Decrypt);
        }
        Ok(decrypted.to_vec())
    }
}
fn binding(purpose: Purpose, id: Uuid, epoch: Uuid) -> [u8; 34] {
    let mut value = [0u8; 34];
    value[0] = 1;
    value[1] = purpose.byte();
    value[2..18].copy_from_slice(id.as_bytes());
    value[18..].copy_from_slice(epoch.as_bytes());
    value
}
pub fn random_token() -> Result<String, SessionCryptoError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| SessionCryptoError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub fn token_hash(token: &str) -> Result<String, SessionCryptoError> {
    use sha2::{Digest, Sha256};
    if token.len() != 43 {
        return Err(SessionCryptoError::Decrypt);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| SessionCryptoError::Decrypt)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(SessionCryptoError::Decrypt);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn keys(active: &str, ids: &[&str]) -> SessionKeys {
        SessionKeys::parse(&serde_json::to_vec(&serde_json::json!({"active":active,"keys":ids.iter().map(|id|serde_json::json!({"id":id,"key":URL_SAFE_NO_PAD.encode([id.as_bytes()[0];32])})).collect::<Vec<_>>()})).unwrap()).unwrap()
    }
    #[test]
    fn encrypted_records_bind_purpose_record_epoch_and_detect_tampering() {
        let k = keys("a", &["a"]);
        let id = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let raw = b"ACCESS_REFRESH_TOKEN_MARKER";
        let encrypted = k.encrypt(Purpose::Session, id, epoch, raw).unwrap();
        assert!(!encrypted.windows(raw.len()).any(|part| part == raw));
        assert_eq!(
            k.decrypt(Purpose::Session, id, epoch, &encrypted).unwrap(),
            raw
        );
        assert!(k.decrypt(Purpose::Login, id, epoch, &encrypted).is_err());
        assert!(
            k.decrypt(Purpose::Session, Uuid::new_v4(), epoch, &encrypted)
                .is_err()
        );
        assert!(
            k.decrypt(Purpose::Session, id, Uuid::new_v4(), &encrypted)
                .is_err()
        );
        let mut forged = encrypted.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(k.decrypt(Purpose::Session, id, epoch, &forged).is_err());
        assert_ne!(
            k.encrypt(Purpose::Session, id, epoch, raw).unwrap(),
            encrypted
        );
        for length in 0..encrypted.len() {
            assert!(
                k.decrypt(Purpose::Session, id, epoch, &encrypted[..length])
                    .is_err()
            );
        }
    }
    #[test]
    fn rotation_retains_only_explicit_old_keys_and_tokens_are_canonical() {
        let id = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let old = keys("a", &["a"])
            .encrypt(Purpose::Login, id, epoch, b"pkce-verifier")
            .unwrap();
        assert_eq!(
            keys("b", &["a", "b"])
                .decrypt(Purpose::Login, id, epoch, &old)
                .unwrap(),
            b"pkce-verifier"
        );
        assert!(
            keys("b", &["b"])
                .decrypt(Purpose::Login, id, epoch, &old)
                .is_err()
        );
        let token = random_token().unwrap();
        assert_eq!(token.len(), 43);
        assert_eq!(token_hash(&token).unwrap().len(), 64);
        assert!(token_hash(&(token + "=")).is_err());
        let invalid = b"{\"active\":\"SECRET_MUST_NOT_ECHO\",\"keys\":[]}";
        assert_eq!(
            SessionKeys::parse(invalid).err().unwrap().to_string(),
            "invalid browser-session encryption key configuration"
        );
    }
}
