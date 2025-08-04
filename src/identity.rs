use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, spki::der::pem::LineEnding},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512};
use std::time::Duration;
use std::{
    fmt::{self, Display},
    path::Path,
};
use std::{fs, path::PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityIoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("pem error: {0}")]
    PemError(#[from] ed25519_dalek::pkcs8::Error),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error("file stores a wrong identity")]
    IdentityMismatch,

    #[error("bogus key")]
    BogusKey,

    #[error(transparent)]
    IdentityError(#[from] IdentityError),
}

type IoResult<T> = std::result::Result<T, IdentityIoError>;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("bogus certificate")]
    BogusCertificate,

    #[error("certificate is valid between {valid_since} and {valid_until}, but not now ({now})")]
    CertificateExpired {
        valid_since: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        now: DateTime<Utc>,
    },
}

#[derive(Error, Debug)]
pub enum IdenitySignError {
    #[error("wrong issuer: requested={requested:?}, signatory={signatory:?}")]
    WrongIssuer {
        requested: VerifyingKey,
        signatory: VerifyingKey,
    },
}

type SignResult<T> = std::result::Result<T, IdenitySignError>;

#[derive(Debug, Clone)]
pub struct SigningKeyHex(SigningKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    Ok,
    Failed,
}

type Result<T> = std::result::Result<T, IdentityError>;

/// An identity that possesses a private key and can create signatures.
#[derive(Debug, Clone)]
pub struct SoftwareIdentity(SigningKeyHex);

impl SoftwareIdentity {
    pub fn new(key: SigningKey) -> Self {
        Self(SigningKeyHex(key))
    }

    pub fn key(&self) -> &SigningKey {
        &self.0.0
    }

    pub fn verifying_identity(&self) -> VerifyingIdentity {
        VerifyingIdentity::new(self.key().verifying_key())
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKeyHex(VerifyingKey);

#[derive(Debug, Clone)]
struct SignatureHex(Signature);

/// An identity whose public key and certificate are known, used for verification.
#[derive(Clone, Debug)]
pub struct VerifyingIdentity(VerifyingKeyHex);

impl VerifyingIdentity {
    pub fn new(key: VerifyingKey) -> Self {
        Self(VerifyingKeyHex(key))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0.0.as_bytes())
    }

    fn key(&self) -> &VerifyingKey {
        self.0.key()
    }
}

pub trait Payload: Clone {
    type Bytes: AsRef<[u8]>;

    fn to_bytes(&self) -> Self::Bytes;
}

impl<T: Serialize + Clone> Payload for T {
    type Bytes = Vec<u8>;
    fn to_bytes(&self) -> Self::Bytes {
        serde_json::to_vec(self).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedMessage<P: Payload> {
    payload: P,
    signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerIdentity {
    pub server_pubkey: VerifyingKeyHex,
    pub issuer_pubkey: VerifyingKeyHex,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerCertificate(SignedMessage<ServerIdentity>);

impl ServerCertificate {
    pub fn new(payload: ServerIdentity, identity: &impl SigningIdentity) -> SignatureResult<Self> {
        Ok(Self(SignedMessage::new(payload, identity)?))
    }

    pub fn check(&self, now: DateTime<Utc>) -> Result<()> {
        let srv_identity = self.0.payload();

        if self.0.verify(&VerifyingIdentity::new(
            srv_identity.issuer_pubkey.key().clone(),
        )) != VerifyStatus::Ok
            || self.0.payload.issued_at > self.0.payload.expires_at
        {
            return Err(IdentityError::BogusCertificate);
        }

        if now < srv_identity.issued_at || srv_identity.expires_at < now {
            return Err(IdentityError::CertificateExpired {
                valid_since: srv_identity.issued_at,
                valid_until: srv_identity.expires_at,
                now,
            });
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    Server,
    Admin,
    Reader,
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

impl SoftwareIdentity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let keypair = SigningKey::generate(&mut rng);
        SoftwareIdentity::new(keypair)
    }

    pub fn sign_prehashed(&self, digest: Sha512) -> SignatureResult<Signature> {
        self.key()
            .sign_prehashed(digest, None)
            .map_err(|e| SignatureError(e.to_string()))
    }

    pub fn load(dir: &Path, subject: &VerifyingIdentity) -> IoResult<Self> {
        let keypair = SigningKey::read_pkcs8_pem_file(_filename(dir, subject.key(), "key"))?;
        match &keypair.verifying_key() == subject.key() {
            true => Ok(SoftwareIdentity::new(keypair)),
            false => Err(IdentityIoError::IdentityMismatch),
        }
    }

    pub fn save(&self, dir: &Path) -> IoResult<PathBuf> {
        let key_path = _filename(dir, self.verifying_identity().key(), "key");
        self.key().write_pkcs8_pem_file(&key_path, LineEnding::LF)?;
        Ok(key_path)
    }
}

impl VerifyingIdentity {
    pub fn verify_prehashed(&self, digest: Sha512, signature: &Signature) -> VerifyStatus {
        match self.key().verify_prehashed(digest, None, signature) {
            Ok(_) => VerifyStatus::Ok,
            Err(_) => VerifyStatus::Failed,
        }
    }
}

impl<P: Payload> SignedMessage<P> {
    pub fn new(payload: P, identity: &impl SigningIdentity) -> SignatureResult<Self> {
        let sig = identity.sign_prehashed(Self::_prehash(&payload))?;
        Ok(Self {
            payload,
            signature: sig.into(),
        })
    }

    pub fn verify(&self, identity: &VerifyingIdentity) -> VerifyStatus {
        identity.verify_prehashed(Self::_prehash(&self.payload), self.signature())
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    fn _prehash(payload: &P) -> Sha512 {
        let bytes = payload.to_bytes();
        let mut prehashed = Sha512::new();
        prehashed.update(&bytes);
        prehashed
    }
}

fn _filename(dir: &Path, subject_pubkey: &VerifyingKey, ext: &str) -> PathBuf {
    dir.join(hex::encode(subject_pubkey.as_bytes()))
        .with_extension(ext)
}

impl VerifyingKeyHex {
    pub fn new(key: VerifyingKey) -> Self {
        Self(key)
    }

    pub fn key(&self) -> &VerifyingKey {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }
}

impl From<VerifyingKey> for VerifyingKeyHex {
    fn from(key: VerifyingKey) -> Self {
        VerifyingKeyHex::new(key)
    }
}

impl TryFrom<&str> for VerifyingKeyHex {
    type Error = IdentityIoError;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|_| IdentityIoError::BogusKey)?;
        let key_bytes = &bytes.try_into().map_err(|_| IdentityIoError::BogusKey)?;
        Ok(VerifyingKeyHex::new(
            VerifyingKey::from_bytes(key_bytes).map_err(|_| IdentityIoError::BogusKey)?,
        ))
    }
}

impl Serialize for VerifyingKeyHex {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for VerifyingKeyHex {
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
            .map(VerifyingKeyHex)
            .map_err(serde::de::Error::custom)
    }
}

impl SignatureHex {
    pub fn new(signature: Signature) -> Self {
        Self(signature)
    }

    pub fn signature(&self) -> &Signature {
        &self.0
    }
}

impl From<Signature> for SignatureHex {
    fn from(signature: Signature) -> Self {
        SignatureHex::new(signature)
    }
}

impl Serialize for SignatureHex {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for SignatureHex {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let sig_bytes = &bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        Ok(Signature::from_bytes(sig_bytes).into())
    }
}

#[derive(Error, Debug)]
#[error("signature failed: {0}")]
pub struct SignatureError(String);

type SignatureResult<T> = std::result::Result<T, SignatureError>;

pub trait SigningIdentity {
    fn sign_prehashed(&self, prehashed: Sha512) -> SignatureResult<Signature>;
}

impl SigningIdentity for SoftwareIdentity {
    fn sign_prehashed(&self, prehashed: Sha512) -> SignatureResult<Signature> {
        self.sign_prehashed(prehashed)
    }
}
