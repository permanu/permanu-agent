use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const AGENT_PRIVKEY_PATH: &str = "/var/lib/permanu-agent/agent_x25519.key";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const EPHEMERAL_PUBKEY_LEN: usize = 32;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum CryptoError {
    #[error("keypair load failed: {path}: {reason}")]
    KeypairLoad { path: String, reason: String },

    #[error("keypair length mismatch: {path}: got {length} bytes, want 32")]
    KeypairLength { path: String, length: usize },

    #[error("key generation failed: {reason}")]
    KeyGeneration { reason: String },

    #[error("key persist failed: {path}: {reason}")]
    KeyPersist { path: String, reason: String },

    #[error("sealed box too short: got {length} bytes, need >= {required}")]
    BlobTooShort { length: usize, required: usize },

    #[error("cipher creation failed: {reason}")]
    CipherCreate { reason: String },

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("path has no parent directory: {path}")]
    NoParent { path: String },

    #[error("IO error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Io {
            path: String::new(),
            source: err,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentKeypair {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl AgentKeypair {
    pub fn load_or_generate_default() -> Result<Self, CryptoError> {
        let path = std::env::var("PERMANU_AGENT_X25519_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(AGENT_PRIVKEY_PATH));
        Self::load_or_generate(path)
    }

    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        match fs::read(path) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(CryptoError::KeypairLength {
                        path: path.display().to_string(),
                        length: bytes.len(),
                    });
                }
                let mut private_key = [0_u8; 32];
                private_key.copy_from_slice(&bytes);
                Ok(Self::from_private_key(private_key))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut private_key = [0_u8; 32];
                getrandom::getrandom(&mut private_key).map_err(|err| {
                    CryptoError::KeyGeneration {
                        reason: format!("generate X25519 private key: {err}"),
                    }
                })?;
                clamp_x25519_private_key(&mut private_key);
                persist_private_key(path, &private_key)?;
                Ok(Self::from_private_key(private_key))
            }
            Err(err) => Err(CryptoError::Io {
                path: path.display().to_string(),
                source: err,
            }),
        }
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = PublicKey::from(&StaticSecret::from(private_key));
        Self {
            private_key,
            public_key: public_key.to_bytes(),
        }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn open_from_agent(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let min_len = EPHEMERAL_PUBKEY_LEN + NONCE_LEN + TAG_LEN;
        if blob.len() < min_len {
            return Err(CryptoError::BlobTooShort {
                length: blob.len(),
                required: min_len,
            });
        }

        let mut ephemeral = [0_u8; EPHEMERAL_PUBKEY_LEN];
        ephemeral.copy_from_slice(&blob[..EPHEMERAL_PUBKEY_LEN]);
        let shared =
            StaticSecret::from(self.private_key).diffie_hellman(&PublicKey::from(ephemeral));
        let cipher = Aes256Gcm::new_from_slice(shared.as_bytes()).map_err(|err| {
            CryptoError::CipherCreate {
                reason: format!("agent_box: create AES-256-GCM cipher: {err}"),
            }
        })?;
        let nonce =
            Nonce::from_slice(&blob[EPHEMERAL_PUBKEY_LEN..EPHEMERAL_PUBKEY_LEN + NONCE_LEN]);
        cipher
            .decrypt(nonce, &blob[EPHEMERAL_PUBKEY_LEN + NONCE_LEN..])
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

fn clamp_x25519_private_key(private_key: &mut [u8; 32]) {
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
}

fn persist_private_key(path: &Path, private_key: &[u8; 32]) -> Result<(), CryptoError> {
    let dir = path.parent().ok_or_else(|| CryptoError::NoParent {
        path: path.display().to_string(),
    })?;
    fs::create_dir_all(dir).map_err(|err| CryptoError::Io {
        path: dir.display().to_string(),
        source: err,
    })?;
    let tmp = path.with_extension("key.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(|err| CryptoError::Io {
        path: tmp.display().to_string(),
        source: err,
    })?;
    if let Err(err) = file.write_all(private_key).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(CryptoError::Io {
            path: tmp.display().to_string(),
            source: err,
        });
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(|err| {
            CryptoError::Io {
                path: tmp.display().to_string(),
                source: err,
            }
        })?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(CryptoError::Io {
            path: format!("{} -> {}", tmp.display(), path.display()),
            source: err,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;

    #[test]
    fn keypair_load_generates_persistent_public_key() {
        let dir =
            std::env::temp_dir().join(format!("permanu-agent-keypair-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("agent_x25519.key");

        let first = AgentKeypair::load_or_generate(&path).expect("generate keypair");
        let second = AgentKeypair::load_or_generate(&path).expect("load keypair");
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(fs::read(path).expect("read private key").len(), 32);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn opens_go_compatible_seal_for_agent_blob() {
        let agent = AgentKeypair::from_private_key([7_u8; 32]);
        let mut ephemeral_priv = [11_u8; 32];
        clamp_x25519_private_key(&mut ephemeral_priv);
        let ephemeral_secret = StaticSecret::from(ephemeral_priv);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let agent_pub = PublicKey::from(*agent.public_key());
        let shared = ephemeral_secret.diffie_hellman(&agent_pub);
        let cipher = Aes256Gcm::new_from_slice(shared.as_bytes()).expect("cipher");
        let nonce = [3_u8; NONCE_LEN];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), b"secret".as_slice())
            .expect("encrypt");

        let mut blob = Vec::new();
        blob.extend_from_slice(ephemeral_pub.as_bytes());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        assert_eq!(agent.open_from_agent(&blob).expect("open"), b"secret");
    }
}
