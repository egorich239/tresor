use std::path::PathBuf;

use crate::{
    api::{IdentityRequest, IdentityResponse},
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
    let req = IdentityRequest::Add { name, key, role };
    let res: IdentityResponse = session.query("identity", req)?;
    match res {
        IdentityResponse::Success => println!("identity added"),
        IdentityResponse::AlreadyExists => println!("identity already exists"),
    };
    Ok(())
}
