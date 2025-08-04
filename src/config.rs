use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

use crate::identity::VerifyingIdentity;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("failed to parse config file: {0}")]
    InvalidConfigSyntax(#[from] toml::de::Error),
}

#[derive(Deserialize)]
pub struct Config {
    pub srv: Srv,
    pub backup: Backup,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}

/// A wrapper around PathBuf to provide helper methods for accessing data files.
#[derive(Clone)]
pub struct DataStore(PathBuf);

impl<'de> Deserialize<'de> for DataStore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        PathBuf::deserialize(deserializer).map(DataStore)
    }
}

impl DataStore {
    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn db_path(&self) -> PathBuf {
        self.path().join("tresor.db")
    }

    pub fn identities_dir(&self) -> PathBuf {
        self.path().join("identities")
    }

    pub fn root_key_symlink(&self) -> PathBuf {
        self.path().join("root.crt")
    }

    pub fn srv_key_symlink(&self) -> PathBuf {
        self.path().join("srv.crt")
    }

    /// Location of server certificates, signed by identities.
    pub fn server_certs_dir(&self) -> PathBuf {
        self.path().join("server_certs")
    }

    pub fn server_cert_dir(&self, client: &VerifyingIdentity) -> PathBuf {
        self.server_certs_dir().join(client.hex())
    }

    pub fn file_by_identity(identity: &VerifyingIdentity, ext: &str) -> PathBuf {
        PathBuf::from(identity.hex()).with_extension(ext)
    }
}

#[derive(Deserialize)]
pub struct Srv {
    pub data: DataStore,
    #[serde(flatten)]
    pub config: SrvConfig,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct SrvConfig {
    #[serde(with = "humantime_serde")]
    pub sw_identity_rot_period: Duration,

    #[serde(with = "humantime_serde")]
    pub max_session_duration: Duration,
}

#[derive(Deserialize)]
pub struct Backup {
    pub dir: PathBuf,
}
