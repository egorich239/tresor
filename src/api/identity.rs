use serde::{Deserialize, Serialize};

use crate::{api::ServerCertificate, identity::IdentityRole};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum IdentityRequest {
    Add {
        name: String,
        role: IdentityRole,
        certificate: ServerCertificate,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum IdentityResponse {
    Success,
    AlreadyExists,
}
