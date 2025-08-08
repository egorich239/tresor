use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha512;
use std::fmt::{self, Display};
use std::io;
use thiserror::Error;

mod software;
pub use software::*;

#[derive(Error, Debug, Serialize, Deserialize)]
#[error("signature failed: {0}")]
pub struct SignatureError(String);

pub type SignatureResult<T> = std::result::Result<T, SignatureError>;

impl SignatureError {
    pub fn new(e: impl Display) -> Self {
        Self(e.to_string())
    }
}

pub trait SigningIdentity {
    fn verifying_identity(&self) -> VerifyingIdentity;

    fn sign_prehashed(&self, prehashed: Sha512) -> SignatureResult<Signature>;
}

/// An identity whose public key and certificate are known, used for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingIdentity(VerifyingKey);

impl Display for VerifyingIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingIdentity({})", self.hex())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    Server,
    Admin,
    Reader,
}

impl From<char> for IdentityRole {
    fn from(c: char) -> Self {
        match c {
            's' => IdentityRole::Server,
            'a' => IdentityRole::Admin,
            'r' => IdentityRole::Reader,
            _ => panic!("invalid identity role: {c}"),
        }
    }
}

impl TryFrom<&str> for IdentityRole {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "server" => Ok(IdentityRole::Server),
            "admin" => Ok(IdentityRole::Admin),
            "reader" => Ok(IdentityRole::Reader),
            _ => Err(()),
        }
    }
}

impl Display for IdentityRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityRole::Server => write!(f, "server"),
            IdentityRole::Admin => write!(f, "admin"),
            IdentityRole::Reader => write!(f, "reader"),
        }
    }
}

impl VerifyingIdentity {
    pub fn new(key: VerifyingKey) -> Self {
        Self(key)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    pub fn verify_prehashed(&self, digest: Sha512, signature: &Signature) -> bool {
        self.key().verify_prehashed(digest, None, signature).is_ok()
    }

    fn key(&self) -> &VerifyingKey {
        &self.0
    }
}

impl TryFrom<&str> for VerifyingIdentity {
    type Error = io::Error;
    fn try_from(s: &str) -> io::Result<Self> {
        let bytes = hex::decode(s).map_err(|_| io::Error::other("bogus key"))?;
        let key_bytes = &bytes
            .try_into()
            .map_err(|_| io::Error::other("bogus key"))?;
        Ok(VerifyingIdentity::new(
            VerifyingKey::from_bytes(key_bytes).map_err(|_| io::Error::other("bogus key"))?,
        ))
    }
}

impl Serialize for VerifyingIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for VerifyingIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let key_bytes = &bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        VerifyingKey::from_bytes(key_bytes)
            .map(VerifyingIdentity::new)
            .map_err(serde::de::Error::custom)
    }
}
