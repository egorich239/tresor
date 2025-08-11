use crate::{
    api::{ClaimRequest, ClaimResponse, IdentityRequest, IdentityResponse, ServerCertificate},
    cli::{ClientResult, Session},
    identity::{IdentityRole, SigningIdentity},
};

pub fn identity_add(
    session: &Session,
    role: IdentityRole,
    name: String,
    identity: Box<dyn SigningIdentity>,
) -> ClientResult<()> {
    let key = identity.verifying_identity();
    let claim: ClaimResponse = session.query("claim", ClaimRequest { issuer: key })?;
    let certificate = ServerCertificate::new(claim.claim, &*identity)?;
    let _res: IdentityResponse = session.query(
        "identity",
        IdentityRequest::Add {
            name,
            role,
            certificate,
        },
    )?;
    println!("identity added");
    Ok(())
}
