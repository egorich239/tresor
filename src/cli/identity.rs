use std::{fs, path::PathBuf};

use crate::{
    api::identity::{IdentityRequest, IdentityResponse},
    cli::{session::Session, ClientError, ClientResult},
    identity::{IdentityRole, SigningIdentity, VerifyingIdentity},
};
use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey};

pub enum PubkeySource {
    Inline(String),
    PrivateKeyFile(PathBuf),
    PublicKeyFile(PathBuf),
}

fn load_pubkey(src: PubkeySource) -> ClientResult<VerifyingIdentity> {
    match src {
        PubkeySource::Inline(s) => {
            let pem = format!("-----BEGIN PUBLIC KEY-----\n{s}\n-----END PUBLIC KEY-----\n");
            let key = VerifyingKey::from_public_key_pem(&pem)
                .map_err(|_| ClientError::InvalidIdentity)?;
            Ok(VerifyingIdentity::new(key))
        }
        PubkeySource::PrivateKeyFile(path) => {
            let pem = fs::read_to_string(path)?;
            let sk = SigningKey::from_pkcs8_pem(&pem).map_err(|_| ClientError::InvalidIdentity)?;
            Ok(VerifyingIdentity::new(sk.verifying_key()))
        }
        PubkeySource::PublicKeyFile(path) => {
            let pem = fs::read_to_string(path)?;
            let vk = VerifyingKey::from_public_key_pem(&pem)
                .map_err(|_| ClientError::InvalidIdentity)?;
            Ok(VerifyingIdentity::new(vk))
        }
    }
}

pub fn identity_add(
    session: &Session,
    role: IdentityRole,
    name: String,
    identity: Box<dyn SigningIdentity>,
) -> ClientResult<()> {
    let key = identity.verifying_identity();
    let req = IdentityRequest::Add { name, key, role };
    let res: IdentityResponse = session.query("identity", req)?;
    match res {
        IdentityResponse::Success => println!("identity added"),
        IdentityResponse::AlreadyExists => println!("identity already exists"),
    };
    Ok(())
}
