use std::fmt;

use crate::{
    age::RecepientStr,
    api::{RandomBytes, ServerCertificate, SignedMessage},
    identity::VerifyingIdentity,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type SessionRequest = SignedMessage<SessionRequestPayload>;

#[derive(Clone)]
pub struct SessionEncKey(RandomBytes<32>);

pub type Nonce = RandomBytes<16>;
pub type SessionId = RandomBytes<16>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRequestPayload {
    pub nonce: Nonce,
    pub identity: VerifyingIdentity,
    pub recepient: RecepientStr,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionResponsePayload {
    pub nonce: Nonce,
    pub session_id: SessionId,
    pub certificate: ServerCertificate,
    pub enc_key: SessionEncKey,
}

pub type SessionResponse = SignedMessage<SessionResponsePayload>;

impl SessionEncKey {
    pub fn generate() -> Self {
        Self(RandomBytes::generate())
    }
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SessionEncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionEncKey({})", self.to_hex())
    }
}

impl Serialize for SessionEncKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SessionEncKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(RandomBytes::deserialize(deserializer)?))
    }
}
