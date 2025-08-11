use serde::{Deserialize, Serialize};

/// `POST /env` endpoint request payload.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum EnvRequest {
    Create {
        /// name of the environment being created
        env: String,
        /// list of (env var name, key name) pairs to associate
        pairs: Vec<Envvar>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envvar {
    pub var: String,
    pub value: String,
}

pub type Env = Vec<Envvar>;

/// Response for environment operations
#[derive(Serialize, Deserialize, Debug)]
pub struct EnvResponse;
