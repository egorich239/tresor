use serde::{Deserialize, Serialize};

use crate::identity::{IdentityRole, VerifyingIdentity};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum IdentityRequest {
    Add {
        name: String,
        key: VerifyingIdentity,
        role: IdentityRole,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum IdentityResponse {
    Success,
    AlreadyExists,
}
