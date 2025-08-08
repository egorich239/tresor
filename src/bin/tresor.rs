use std::{io, path::PathBuf};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use reqwest::blocking::Client;
use tresor::{
    cli::{
        ClientError, ClientResult,
        env::env_create,
        identity::{PubkeySource, identity_add},
        secret_edit,
        session::request_session,
    },
    config::{Config, ConfigError},
    identity::{IdentityRole, SigningIdentity, SoftwareIdentity},
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
enum SecretAction {
    Edit { script: PathBuf },
}

#[derive(Parser)]
struct SecretCommands {
    #[command(subcommand)]
    action: SecretAction,
}

#[derive(Subcommand)]
enum EnvAction {
    Create { file: PathBuf },
}

#[derive(Parser)]
struct EnvCommands {
    #[command(subcommand)]
    action: EnvAction,
}

#[derive(Subcommand)]
enum Commands {
    Ping,
    Secret(SecretCommands),
    Env(EnvCommands),
    Identity(IdentityCommands),
}
#[derive(Subcommand, Debug)]
enum IdentityAction {
    Add(IdentityAddArgs),
}

#[derive(Args, Debug)]
struct IdentityAddArgs {
    #[arg(value_enum)]
    role: IdentityRole,
    name: String,
    /// Inline PEM payload (base64, without header/footer)
    #[arg(conflicts_with_all = ["key", "pubkey"])]
    inline: Option<String>,
    /// Private key PEM file to derive pubkey from
    #[arg(short = 'k', long = "key", conflicts_with = "pubkey")]
    key: Option<PathBuf>,
    /// Public key PEM file
    #[arg(short = 'p', long = "pubkey")]
    pubkey: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct IdentityCommands {
    #[command(subcommand)]
    action: IdentityAction,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let identity @ Identity::Software { port, .. } = Identity::new(cli.identity)?;
    let identity = identity.build()?;

    let client = Client::new();
    let server_url = format!("http://localhost:{port}");

    match cli.command {
        Commands::Ping => {
            request_session(&client, identity.as_ref(), &server_url)?;
            println!("Successfully established a session");
        }
        Commands::Secret(secret_cmd) => {
            let session = request_session(&client, identity.as_ref(), &server_url)?;
            match secret_cmd.action {
                SecretAction::Edit { script } => secret_edit(&session, script)?,
            };
        }
        Commands::Env(env_cmd) => {
            let session = request_session(&client, identity.as_ref(), &server_url)?;
            match env_cmd.action {
                EnvAction::Create { file } => env_create(&session, file)?,
            };
        }
        Commands::Identity(id_cmd) => {
            let session = request_session(&client, identity.as_ref(), &server_url)?;
            match id_cmd.action {
                IdentityAction::Add(args) => {
                    let key_src = if let Some(s) = args.inline {
                        PubkeySource::Inline(s)
                    } else if let Some(k) = args.key {
                        PubkeySource::PrivateKeyFile(k)
                    } else if let Some(p) = args.pubkey {
                        PubkeySource::PublicKeyFile(p)
                    } else {
                        return Err(anyhow::anyhow!("no key provided: use inline, -k or -p"));
                    };
                    identity_add(&session, args.role, args.name, key_src)?
                }
            }
        }
    };
    Ok(())
}
