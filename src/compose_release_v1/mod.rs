//! Fixture-only Compose v1 agent boundary. This module has no socket/RPC route,
//! signer, enrollment, command runner, or production transport implementation.
//! Enabling its Cargo feature does not enable it at runtime.

#[cfg(feature = "compose-release-v1")]
pub(crate) mod authority;
mod generated;
mod schema;
#[cfg(feature = "compose-release-v1")]
pub(crate) mod standing;
#[cfg(feature = "compose-release-v1")]
pub(crate) mod standing_store;
#[cfg(test)]
mod tests;
#[cfg(feature = "compose-release-v1")]
mod typed;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use generated::CAPABILITY;
const MAX_BYTES: usize = generated::MAX_ENVELOPE_BYTES;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Disabled,
    Parse,
    Binding,
    Authority,
    Transport,
}

/// The trusted adapter must verify both domain-separated signatures against
/// current enrolled policy and role-specific, unrevoked public keys. It must
/// also check exact policy/target/config/source/artifact binding and all gates.
/// No implementation is installed; request JSON cannot supply this adapter.
pub trait AdmissionVerifier {
    fn verify(&self, envelope: &Value, now: i64) -> Result<(), Error>;
}
/// A fixture transport only. Implementations must bound/cancel their own I/O.
/// Production socket/SSH or unrestricted command adapters are not provided.
pub trait FixtureTransport {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, Error>;
}
#[derive(Default)]
pub struct Boundary {
    enabled: bool,
}
impl Boundary {
    pub fn negotiate(mut self, agent: Option<&str>, runner: Option<&str>) -> Result<Self, Error> {
        if agent != Some(CAPABILITY) || runner != Some(CAPABILITY) {
            return Err(Error::Disabled);
        }
        self.enabled = true;
        Ok(self)
    }
    pub fn bind<V: AdmissionVerifier, T: FixtureTransport>(
        self,
        verifier: V,
        transport: T,
    ) -> Bridge<V, T> {
        Bridge {
            boundary: self,
            verifier,
            transport,
        }
    }
}
pub struct Bridge<V, T> {
    boundary: Boundary,
    verifier: V,
    transport: T,
}
/// Fields are private: caller data alone cannot manufacture a prepared handle.
pub struct Prepared {
    envelope: Value,
    release_digest: String,
    application_id: String,
    release_id: String,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FixtureReceipt {
    pub version: u32,
    pub capability: String,
    pub state: String,
    pub release_digest: String,
    pub application_id: String,
    pub release_id: String,
}
impl<V: AdmissionVerifier, T: FixtureTransport> Bridge<V, T> {
    pub fn prepare(&self, raw: &[u8], now: i64) -> Result<Prepared, Error> {
        if !self.boundary.enabled {
            return Err(Error::Disabled);
        }
        let envelope = schema::parse(raw, now)?;
        self.verifier
            .verify(&envelope, now)
            .map_err(|_| Error::Authority)?;
        Ok(Prepared {
            release_digest: schema::digest(
                generated::RELEASE_DOMAIN.as_bytes(),
                &envelope["release"],
            )?,
            application_id: envelope["release"]["application_id"]
                .as_str()
                .ok_or(Error::Parse)?
                .to_owned(),
            release_id: envelope["release"]["release_id"]
                .as_str()
                .ok_or(Error::Parse)?
                .to_owned(),
            envelope,
        })
    }
    pub fn dispatch(&self, prepared: &Prepared, now: i64) -> Result<FixtureReceipt, Error> {
        if !self.boundary.enabled {
            return Err(Error::Disabled);
        }
        let raw = serde_json::to_vec(&prepared.envelope).map_err(|_| Error::Parse)?;
        schema::parse(&raw, now)?;
        self.verifier
            .verify(&prepared.envelope, now)
            .map_err(|_| Error::Authority)?;
        let request=serde_json::to_vec(&json!({"version":1,"capability":CAPABILITY,"op":"compose.release.fixture","envelope":prepared.envelope})).map_err(|_|Error::Parse)?;
        if request.len() > MAX_BYTES {
            return Err(Error::Parse);
        }
        let response = self
            .transport
            .exchange(&request)
            .map_err(|_| Error::Transport)?;
        let parsed =
            crate::signed_plan::jcs::parse_strict(&response, 4096).ok_or(Error::Transport)?;
        let receipt: FixtureReceipt =
            serde_json::from_value(parsed).map_err(|_| Error::Transport)?;
        if receipt.version != 1
            || receipt.capability != CAPABILITY
            || receipt.state != "fixture_validated"
            || receipt.release_digest != prepared.release_digest
            || receipt.application_id != prepared.application_id
            || receipt.release_id != prepared.release_id
        {
            return Err(Error::Binding);
        }
        Ok(receipt)
    }
}
