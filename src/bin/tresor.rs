use std::{fs, io, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use tresor::{
    cli::{ClientError, ClientResult, session::request_session},
    config::{Config, ConfigError},
    identity::{SigningIdentity, SoftwareIdentity},
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    identity: IdentityArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
#[group(required = true, multiple = false)]
struct IdentityArgs {
    #[arg(short('R'), long, group = "identity")]
    root: Option<PathBuf>,
}

enum Identity {
    Software {
        identity: SoftwareIdentity,
        port: u16,
    },
}

impl Identity {
    pub fn new(args: IdentityArgs) -> ClientResult<Identity> {
        let config = Config::load(args.root.as_ref().unwrap())?;
        let identities_dir = config.srv.data.identities_dir();
        let path = fs::canonicalize(config.srv.data.root_key_symlink()).map_err(Self::_rce)?;
        let stem = path
            .file_stem()
            .ok_or_else(|| Self::_rce(io::Error::other("cannot determine root identity")))?
            .to_str()
            .unwrap();
        let stem = stem.try_into().map_err(Self::_rce)?;
        let root = SoftwareIdentity::load(&identities_dir, &stem).map_err(Self::_rce)?;
        Ok(Identity::Software {
            identity: root,
            port: config.srv.port,
        })
    }

    pub fn build(self) -> ClientResult<Box<dyn SigningIdentity>> {
        match self {
            Identity::Software { identity, .. } => Ok(Box::new(identity)),
        }
    }

    fn _rce(err: io::Error) -> ClientError {
        ClientError::RootConfigError(ConfigError::Io(err))
    }
}

#[derive(Subcommand)]
enum Commands {
    Ping,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let identity @ Identity::Software { port, .. } = Identity::new(cli.identity)?;
    let port = port;
    let identity = identity.build()?;

    let client = Client::new();
    match cli.command {
        Commands::Ping => {
            let session = request_session(
                &client,
                identity.as_ref(),
                &format!("http://localhost:{port}"),
            )?;
            println!("Session: {session:?}");
        }
    }

    // Logic for client-side commands will be added here.
    println!("Tresor CLI (client commands to be implemented)");

    Ok(())
}
