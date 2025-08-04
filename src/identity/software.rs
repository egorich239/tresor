use std::{
    io,
    path::{Path, PathBuf},
};

use ed25519_dalek::{
    Signature, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, spki::der::pem::LineEnding},
};
use rand::rngs::OsRng;
use sha2::Sha512;

use crate::{
    config::DataStore,
    identity::{SignatureResult, SigningIdentity, VerifyingIdentity},
};

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

    pub fn load(dir: &Path, subject: &VerifyingIdentity) -> io::Result<Self> {
        let key_path = dir.join(DataStore::file_by_identity(subject, "key"));
        let keypair = SigningKey::read_pkcs8_pem_file(&key_path).map_err(io::Error::other)?;
        match &keypair.verifying_key() == subject.key() {
            true => Ok(SoftwareIdentity::new(keypair)),
            false => Err(io::Error::other("corrupted key file")),
        }
    }

    pub fn save(&self, dir: &Path) -> io::Result<PathBuf> {
        let key_path = dir.join(DataStore::file_by_identity(
            &self.verifying_identity(),
            "key",
        ));
        self.key()
            .write_pkcs8_pem_file(&key_path, LineEnding::LF)
            .map_err(io::Error::other)?;
        Ok(key_path)
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
