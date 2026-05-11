use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use x25519_dalek::{PublicKey, StaticSecret};

const AGENT_PRIVKEY_PATH: &str = "/var/lib/permanu-agent/agent_x25519.key";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const EPHEMERAL_PUBKEY_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct AgentKeypair {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl AgentKeypair {
    pub fn load_or_generate_default() -> Result<Self> {
        let path = std::env::var("PERMANU_AGENT_X25519_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(AGENT_PRIVKEY_PATH));
        Self::load_or_generate(path)
    }

    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        match fs::read(path) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    bail!(
                        "keypair: {} has unexpected length {} (want 32)",
                        path.display(),
                        bytes.len()
                    );
                }
                let mut private_key = [0_u8; 32];
                private_key.copy_from_slice(&bytes);
                Ok(Self::from_private_key(private_key))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut private_key = [0_u8; 32];
                getrandom::getrandom(&mut private_key)
                    .map_err(|err| anyhow::anyhow!("generate X25519 private key: {err}"))?;
                clamp_x25519_private_key(&mut private_key);
                persist_private_key(path, &private_key)?;
                Ok(Self::from_private_key(private_key))
            }
            Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
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

    pub fn open_from_agent(&self, blob: &[u8]) -> Result<Vec<u8>> {
        let min_len = EPHEMERAL_PUBKEY_LEN + NONCE_LEN + TAG_LEN;
        if blob.len() < min_len {
            bail!(
                "agent_box: blob too short ({} bytes, need >= {min_len})",
                blob.len()
            );
        }

        let mut ephemeral = [0_u8; EPHEMERAL_PUBKEY_LEN];
        ephemeral.copy_from_slice(&blob[..EPHEMERAL_PUBKEY_LEN]);
        let shared =
            StaticSecret::from(self.private_key).diffie_hellman(&PublicKey::from(ephemeral));
        let cipher = Aes256Gcm::new_from_slice(shared.as_bytes())
            .context("agent_box: create AES-256-GCM cipher")?;
        let nonce =
            Nonce::from_slice(&blob[EPHEMERAL_PUBKEY_LEN..EPHEMERAL_PUBKEY_LEN + NONCE_LEN]);
        cipher
            .decrypt(nonce, &blob[EPHEMERAL_PUBKEY_LEN + NONCE_LEN..])
            .map_err(|_| anyhow::anyhow!("agent_box: GCM open"))
    }
}

fn clamp_x25519_private_key(private_key: &mut [u8; 32]) {
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
}

fn persist_private_key(path: &Path, private_key: &[u8; 32]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("keypair path has no parent: {}", path.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let tmp = path.with_extension("key.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    if let Err(err) = file.write_all(private_key).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("write {}", tmp.display()));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", tmp.display()))?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()));
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
            std::env::temp_dir().join(format!("permanu-agent-rs-keypair-{}", std::process::id()));
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
