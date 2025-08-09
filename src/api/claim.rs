use serde::{Deserialize, Serialize};

use crate::{api::ServerIdentityClaim, identity::VerifyingIdentity};

#[derive(Serialize, Deserialize, Debug)]
pub struct ClaimRequest {
    pub issuer: VerifyingIdentity,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClaimResponse {
    pub claim: ServerIdentityClaim,
}
