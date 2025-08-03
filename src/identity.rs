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

#[derive(Debug, Clone, Copy)]
pub enum VerifyStatus {
    Ok,
    Failed,
}

type Result<T> = std::result::Result<T, IdentityError>;

/// An identity that possesses a private key and can create signatures.
#[derive(Debug, Clone)]
pub struct SoftwareIdentity {
    keypair: SigningKey,
    verifying_identity: VerifyingIdentity,
}

#[derive(Debug, Clone)]
pub struct VerifyingKeyHex(VerifyingKey);

#[derive(Debug, Clone)]
struct SignatureHex(Signature);

/// An identity whose public key and certificate are known, used for verification.
#[derive(Clone, Debug)]
pub struct VerifyingIdentity {
    certificate: Certificate,
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
pub struct Certificate {
    payload: CertificatePayload,
    signature: SignatureHex,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificatePayload {
    pub subject_pubkey: VerifyingKeyHex,
    pub subject_role: IdentityRole,
    pub issuer_pubkey: VerifyingKeyHex,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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
    /// Creates a new, self-signed identity using the Ed25519ph (pre-hashed) scheme.
    pub fn create_self_signed(valid_since: DateTime<Utc>, valid_for: Duration) -> Self {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        let verifying_key = keypair.verifying_key();

        let payload = CertificatePayload {
            subject_pubkey: VerifyingKeyHex(verifying_key),
            subject_role: IdentityRole::Admin,
            issuer_pubkey: VerifyingKeyHex(verifying_key),
            issued_at: valid_since,
            expires_at: valid_since + valid_for,
        };
        let verifying_identity = VerifyingIdentity {
            certificate: payload._sign(&keypair).expect("should not fail"),
        };

        SoftwareIdentity {
            keypair,
            verifying_identity,
        }
    }

    pub fn create_new_identity(
        &self,
        role: IdentityRole,
        valid_since: DateTime<Utc>,
        valid_for: Duration,
    ) -> SoftwareIdentity {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        let verifying_key = keypair.verifying_key();

        let payload = CertificatePayload {
            subject_pubkey: verifying_key.into(),
            subject_role: role,
            issuer_pubkey: (*self.verifying_identity().key()).into(),
            issued_at: valid_since,
            expires_at: valid_since + valid_for,
        };
        let verifying_identity = VerifyingIdentity {
            certificate: payload._sign(&self.keypair).expect("should not fail"),
        };

        SoftwareIdentity {
            keypair,
            verifying_identity,
        }
    }

    pub fn create_verifying_identity(
        &self,
        payload: CertificatePayload,
    ) -> SignResult<VerifyingIdentity> {
        Ok(VerifyingIdentity {
            certificate: payload._sign(&self.keypair)?,
        })
    }

    pub fn sign<P: Payload>(&self, payload: P) -> SignedMessage<P> {
        let bytes = payload.to_bytes();
        let signature = _sign(&self.keypair, bytes.as_ref());
        SignedMessage { payload, signature }
    }

    pub fn verifying_identity(&self) -> &VerifyingIdentity {
        &self.verifying_identity
    }

    pub fn load(dir: &Path, subject: &VerifyingIdentity) -> IoResult<Self> {
        let keypair = SigningKey::read_pkcs8_pem_file(_filename(dir, subject.key(), "key"))?;
        match &keypair.verifying_key() == subject.key() {
            true => Ok(SoftwareIdentity {
                keypair,
                verifying_identity: subject.clone(),
            }),
            false => Err(IdentityIoError::IdentityMismatch),
        }
    }

    /// Saves the private key (PEM) and certificate (JSON) to the specified directory.
    /// The filenames are derived from the identity's public key.
    pub fn save(&self, dir: &Path) -> IoResult<PathBuf> {
        let pubkey = self.verifying_identity.key();
        let key_path = _filename(dir, pubkey, "key");
        self.keypair
            .write_pkcs8_pem_file(&key_path, LineEnding::LF)?;

        let result = self.verifying_identity().save(dir)?;
        Ok(result)
    }
}

impl VerifyingIdentity {
    pub fn key(&self) -> &VerifyingKey {
        &self.certificate.payload.subject_pubkey.0
    }

    pub fn key_hex(&self) -> String {
        hex::encode(self.key().as_bytes())
    }

    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    pub fn verify<P: Payload>(&self, message: &SignedMessage<P>) -> VerifyStatus {
        let bytes = message.payload.to_bytes();
        let signature = message.signature;
        match _verify(self.key(), bytes.as_ref(), &signature) {
            true => VerifyStatus::Ok,
            false => VerifyStatus::Failed,
        }
    }

    pub fn save(&self, dir: &Path) -> IoResult<PathBuf> {
        let json_bytes = serde_json::to_vec_pretty(&self.certificate)
            .expect("failed to serialize certificate to JSON");
        let path = _filename(dir, self.key(), "crt");
        fs::write(&path, json_bytes)?;
        Ok(path)
    }

    pub fn load(dir: &Path, subject_pubkey: &VerifyingKey, now: DateTime<Utc>) -> IoResult<Self> {
        let cert_json = fs::read_to_string(_filename(dir, subject_pubkey, "crt"))?;
        let certificate: Certificate = serde_json::from_str(&cert_json)?;
        if &certificate.payload.subject_pubkey.0 != subject_pubkey {
            return Err(IdentityIoError::IdentityMismatch);
        }
        certificate.check(now)?;
        Ok(VerifyingIdentity { certificate })
    }
}

impl<P: Payload> SignedMessage<P> {
    pub fn sign(payload: P, identity: &SoftwareIdentity) -> Self {
        identity.sign(payload)
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    pub fn verify(&self, identity: &VerifyingIdentity) -> VerifyStatus {
        identity.verify(self)
    }
}

impl CertificatePayload {
    fn _sign(self, keypair: &SigningKey) -> SignResult<Certificate> {
        if self.issuer_pubkey.0 != keypair.verifying_key() {
            return Err(IdenitySignError::WrongIssuer {
                requested: self.issuer_pubkey.0,
                signatory: keypair.verifying_key(),
            });
        }

        let signature = _sign(keypair, &self.to_bytes());
        let certificate = Certificate {
            payload: self,
            signature: signature.into(),
        };
        Ok(certificate)
    }
}

impl Certificate {
    pub fn payload(&self) -> &CertificatePayload {
        &self.payload
    }

    pub fn check(&self, now: DateTime<Utc>) -> Result<()> {
        if !_verify(
            self.payload.issuer_pubkey.key(),
            &self.payload.to_bytes(),
            self.signature.signature(),
        ) || self.payload.issued_at > self.payload.expires_at
        {
            return Err(IdentityError::BogusCertificate);
        }

        if now < self.payload.issued_at || self.payload.expires_at < now {
            return Err(IdentityError::CertificateExpired {
                valid_since: self.payload.issued_at,
                valid_until: self.payload.expires_at,
                now,
            });
        }
        Ok(())
    }
}
fn _filename(dir: &Path, subject_pubkey: &VerifyingKey, ext: &str) -> PathBuf {
    dir.join(hex::encode(subject_pubkey.as_bytes()))
        .with_extension(ext)
}

fn _sign(issuer: &SigningKey, payload: &[u8]) -> Signature {
    let mut prehashed = Sha512::new();
    prehashed.update(payload);
    issuer
        .sign_prehashed(prehashed, None)
        .expect("signature is not expected to fail")
}

fn _verify(issuer_pubkey: &VerifyingKey, payload: &[u8], signature: &Signature) -> bool {
    let mut prehashed = Sha512::new();
    prehashed.update(payload);
    issuer_pubkey
        .verify_prehashed(prehashed, None, signature)
        .is_ok()
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

pub trait SigningIdentity {
    fn identity(&self) -> &VerifyingIdentity;
    fn sign_prehashed(&self, digest: Sha512) -> std::result::Result<Signature, SignatureError>;
}

impl SigningIdentity for SoftwareIdentity {
    fn identity(&self) -> &VerifyingIdentity {
        &self.verifying_identity
    }

    fn sign_prehashed(&self, digest: Sha512) -> std::result::Result<Signature, SignatureError> {
        self.keypair
            .sign_prehashed(digest, None)
            .map_err(|e| SignatureError(e.to_string()))
    }
}
