use std::{io, path::PathBuf};

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
        let root = SoftwareIdentity::load(&config.srv.data.root_key_symlink())?;
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
