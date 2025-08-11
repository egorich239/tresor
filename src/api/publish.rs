use serde::{Deserialize, Serialize};

use crate::{api::session::SessionEncKey, enc::AesNonce};

#[derive(Serialize, Deserialize, Debug)]
pub struct PublishRequest {
    pub env: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublishResponse {
    pub key: SessionEncKey,
    pub nonce: AesNonce,
    pub endpoint: String,
}
