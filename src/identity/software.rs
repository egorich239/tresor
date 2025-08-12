use std::{io, path::Path};

use ed25519_dalek::{
    Signature, SigningKey,
    ed25519::signature::Signer,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, spki::der::pem::LineEnding},
};
use rand::rngs::OsRng;

use crate::identity::{SignatureError, SignatureResult, SigningIdentity, VerifyingIdentity};

/// An identity that possesses a private key and can create signatures.
#[derive(Debug, Clone)]
pub struct SoftwareIdentity(SigningKey);

impl SoftwareIdentity {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn generate() -> Self {
        let mut rng = OsRng;
        let keypair = SigningKey::generate(&mut rng);
        SoftwareIdentity::new(keypair)
    }

    pub fn verifying_identity(&self) -> VerifyingIdentity {
        VerifyingIdentity::new(self.key().verifying_key())
    }

    pub fn sign(&self, payload: &[u8]) -> SignatureResult<Signature> {
        self.key()
            .try_sign(payload)
            .map_err(|e| SignatureError(e.to_string()))
    }

    pub fn load(file: &Path) -> io::Result<Self> {
        let keypair = SigningKey::read_pkcs8_pem_file(file).map_err(io::Error::other)?;
        Ok(SoftwareIdentity::new(keypair))
    }

    pub fn save(&self, file: &Path) -> io::Result<()> {
        self.key()
            .write_pkcs8_pem_file(file, LineEnding::LF)
            .map_err(io::Error::other)
    }

    fn key(&self) -> &SigningKey {
        &self.0
    }
}

impl SigningIdentity for SoftwareIdentity {
    fn verifying_identity(&self) -> VerifyingIdentity {
        self.verifying_identity()
    }

    fn sign(&self, payload: &[u8]) -> SignatureResult<Signature> {
        self.sign(payload)
    }
}
