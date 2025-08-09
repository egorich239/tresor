use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

use crate::{
    api::{SignedMessage, VerifyStatus},
    config::DataStore,
    identity::{SignatureResult, SigningIdentity, VerifyingIdentity},
};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct ServerIdentityClaim {
    pub server_pubkey: VerifyingIdentity,
    pub issuer_pubkey: VerifyingIdentity,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerCertificate(SignedMessage<ServerIdentityClaim>);

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

    #[error("wrong identity")]
    WrongIdentity,
}

impl ServerCertificate {
    pub fn new(
        payload: ServerIdentityClaim,
        identity: &dyn SigningIdentity,
    ) -> SignatureResult<Self> {
        Ok(Self(SignedMessage::new(payload, identity)?))
    }

    pub fn load(dir: &Path, srv_identity: &VerifyingIdentity) -> io::Result<Self> {
        let cert_path = dir.join(DataStore::file_by_identity(srv_identity, "crt"));
        let cert = serde_json::from_slice(&std::fs::read(&cert_path)?)?;
        Ok(Self(cert))
    }

    pub fn save(&self, dir: &Path) -> io::Result<PathBuf> {
        let cert_path = dir.join(DataStore::file_by_identity(self.identity(), "crt"));
        std::fs::write(&cert_path, serde_json::to_vec(&self.0)?)?;
        Ok(cert_path)
    }

    pub fn identity(&self) -> &VerifyingIdentity {
        &self.0.payload().server_pubkey
    }

    pub fn issuer(&self) -> &VerifyingIdentity {
        &self.0.payload().issuer_pubkey
    }

    pub fn check(
        &self,
        now: DateTime<Utc>,
        expected_srv_identity: &VerifyingIdentity,
        expected_issuer_identity: &VerifyingIdentity,
    ) -> Result<(), IdentityError> {
        let claim = self.0.payload();
        let issuer_identity = &claim.issuer_pubkey;
        let srv_identity = &claim.server_pubkey;

        if self.0.verify(issuer_identity) != VerifyStatus::Ok || claim.issued_at > claim.expires_at
        {
            return Err(IdentityError::BogusCertificate);
        }

        if issuer_identity != expected_issuer_identity || srv_identity != expected_srv_identity {
            return Err(IdentityError::WrongIdentity);
        }

        if now < claim.issued_at || claim.expires_at < now {
            return Err(IdentityError::CertificateExpired {
                valid_since: claim.issued_at,
                valid_until: claim.expires_at,
                now,
            });
        }

        Ok(())
    }

    pub fn matches_claim(&self, claim: &ServerIdentityClaim) -> bool {
        self.0.payload() == claim
    }
}
