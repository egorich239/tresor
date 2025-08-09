use std::{collections::HashMap, fs};

use crate::{
    api::{EnvRequest, EnvResponse, Envvar},
    cli::{ClientError, ClientResult},
};
use serde::Deserialize;
use toml;

#[derive(Deserialize)]
struct Envs(HashMap<String, HashMap<String, String>>);

pub fn env_create(
    session: &crate::cli::session::Session,
    file: std::path::PathBuf,
) -> ClientResult<()> {
    let content = fs::read_to_string(&file).map_err(ClientError::internal)?;
    let Envs(map) = toml::from_str(&content).map_err(ClientError::internal)?;

    let (env, kvs) = map
        .into_iter()
        .next()
        .ok_or_else(|| ClientError::ExpectedOneEnvTable)?;

    let pairs: Vec<Envvar> = kvs
        .into_iter()
        .map(|(var, key)| Envvar { var, key })
        .collect();

    let res: EnvResponse = session.query("env", EnvRequest::Create { env, pairs })?;
    match res {
        EnvResponse::Success => println!("Environment created successfully"),
        EnvResponse::EnvExists => println!("Environment already exists"),
    };
    Ok(())
}
