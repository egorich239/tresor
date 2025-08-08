use serde::{Deserialize, Serialize};

/// `POST /secret` endpoint request payload.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum SecretRequest {
    /// Create a new secret. Fails if it already exists.
    Add {
        name: String,
        value: String,
        description: String,
    },
    /// Update an existing secret. Fails if it does not exist.
    Update { name: String, value: String },
    /// Delete a secret. Fails if it does not exist.
    Delete { name: String },
}

/// Represents a successful response payload.
/// As per the requirements, this is a message that indicates success
/// but is empty of any specific data.
#[derive(Serialize, Deserialize, Debug)]
pub enum SecretResponse {
    Success,
    KeyExists,
    KeyNotFound,
}
