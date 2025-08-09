use std::path::PathBuf;

use crate::{
    api::{ClaimRequest, ClaimResponse, IdentityRequest, IdentityResponse, ServerCertificate},
    cli::{ClientResult, Session},
    identity::{IdentityRole, SigningIdentity},
};

pub enum PubkeySource {
    Inline(String),
    PrivateKeyFile(PathBuf),
    PublicKeyFile(PathBuf),
}

pub fn identity_add(
    session: &Session,
    role: IdentityRole,
    name: String,
    identity: Box<dyn SigningIdentity>,
) -> ClientResult<()> {
    let key = identity.verifying_identity();
    let claim: ClaimResponse = session.query("claim", ClaimRequest { issuer: key })?;
    let certificate = ServerCertificate::new(claim.claim, &*identity)?;
    let res: IdentityResponse = session.query(
        "identity",
        IdentityRequest::Add {
            name,
            role,
            certificate,
        },
    )?;
    match res {
        IdentityResponse::Success => println!("identity added"),
        IdentityResponse::AlreadyExists => println!("identity already exists"),
    };
    Ok(())
}
