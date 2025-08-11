use core::fmt;
use std::{collections::HashMap, fs, path::Path};

use crate::{
    api::{Env, EnvRequest, EnvResponse, Envvar, PublishRequest, PublishResponse},
    cli::{ClientError, ClientResult, Session},
};
use serde::Deserialize;
use shell_quote::{Bash, QuoteRefExt};
use toml;

#[derive(clap::ValueEnum, Clone, Debug)]
#[clap(rename_all = "lowercase")]
pub enum OutputFormat {
    Shell,
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Shell => write!(f, "shell"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

pub fn env_print(env: &Env, format: &OutputFormat) -> ClientResult<()> {
    match format {
        OutputFormat::Shell => {
            for Envvar { var, value } in env {
                let quoted: String = value.quoted(Bash);
                println!("{var}={quoted}");
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(env).map_err(ClientError::internal)?;
            println!("{json}");
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct Envs(HashMap<String, HashMap<String, String>>);

pub fn env_create(session: &Session, file: &Path) -> ClientResult<()> {
    let content = fs::read_to_string(file).map_err(ClientError::internal)?;
    let Envs(map) = toml::from_str(&content).map_err(ClientError::internal)?;

    let (env, kvs) = map
        .into_iter()
        .next()
        .ok_or_else(|| ClientError::ExpectedOneEnvTable)?;

    let pairs: Vec<Envvar> = kvs
        .into_iter()
        .map(|(var, key)| Envvar { var, value: key })
        .collect();

    let _res: EnvResponse = session.query("env", EnvRequest::Create { env, pairs })?;
    println!("environment created");
    Ok(())
}

pub fn env_get(session: &Session, name: &str) -> ClientResult<Env> {
    let res: PublishResponse = session.query(
        "publish",
        PublishRequest {
            env: name.to_string(),
        },
    )?;
    let endpoint_session = session.get_endpoint_session(&res.key);
    endpoint_session.get(&res.endpoint, &res.nonce)
}
