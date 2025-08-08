use std::{io, path::Path};

use ed25519_dalek::{
    Signature, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, spki::der::pem::LineEnding},
};
use rand::rngs::OsRng;
use sha2::Sha512;

use crate::identity::{SignatureResult, SigningIdentity, VerifyingIdentity};

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

    pub fn sign_prehashed(&self, digest: Sha512) -> SignatureResult<Signature> {
        self.key()
            .sign_prehashed(digest, None)
            .map_err(|e| super::SignatureError(e.to_string()))
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

    fn sign_prehashed(&self, prehashed: Sha512) -> SignatureResult<Signature> {
        self.sign_prehashed(prehashed)
    }
}
