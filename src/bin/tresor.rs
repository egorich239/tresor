use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use reqwest::blocking::Client;
use tresor::{
    cli::{
        ClientError, ClientResult, OutputFormat, env_create, env_get, env_print, identity_add,
        request_session, secret_edit,
    },
    config::Config,
    identity::{IdentityRole, SigningIdentity, SoftwareIdentity},
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    identity: SessionIdentityArg,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug)]
struct KeyIdentityArg {
    key: PathBuf,
    host: String,
    port: u16,
}

impl FromStr for KeyIdentityArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_part, addr_part) = s.rsplit_once('@').ok_or("expected key@host:port")?;
        if key_part.is_empty() || addr_part.is_empty() {
            return Err("expected key@host:port".into());
        }
        let (host, port_str) = if addr_part.starts_with('[') {
            let end = addr_part.find(']').ok_or("invalid [host]:port")?;
            let host = &addr_part[1..end];
            let rest = &addr_part[end + 1..];
            let port = rest.strip_prefix(':').ok_or("missing :port")?;
            (host.to_string(), port.to_string())
        } else {
            addr_part
                .rsplit_once(':')
                .map(|(h, p)| (h.to_string(), p.to_string()))
                .ok_or_else(|| "expected host:port".to_string())?
        };
        let port: u16 = port_str.parse().map_err(|_| "invalid port".to_string())?;
        Ok(KeyIdentityArg {
            key: PathBuf::from(key_part),
            host,
            port,
        })
    }
}

#[derive(Parser, Debug)]
#[group(required = true, multiple = false)]
struct SessionIdentityArg {
    #[arg(short('R'), long, group = "session-identity")]
    root: Option<PathBuf>,
    #[arg(short('K'), long, group = "session-identity")]
    identity_key: Option<KeyIdentityArg>,
}

#[derive(Parser, Debug)]
#[group(required = true, multiple = false)]
struct ParamIdentityArg {
    #[arg(short('k'), long, group = "param-identity")]
    key: Option<PathBuf>,
}

impl ParamIdentityArg {
    pub fn build(self) -> ClientResult<Box<dyn SigningIdentity>> {
        let key = SoftwareIdentity::load(&self.key.ok_or(ClientError::InvalidIdentity)?)?;
        Ok(Box::new(key))
    }
}

enum Identity {
    Software {
        identity: SoftwareIdentity,
        host: String,
        port: u16,
    },
}

impl Identity {
    pub fn new(args: SessionIdentityArg) -> ClientResult<Identity> {
        if let Some(root_arg) = args.root {
            let config = Config::load(&root_arg)?;
            let root = SoftwareIdentity::load(&config.srv.data.root_key_symlink())?;
            Ok(Identity::Software {
                identity: root,
                host: "localhost".to_string(),
                port: config.srv.port,
            })
        } else if let Some(key_arg) = args.identity_key {
            let key = SoftwareIdentity::load(&key_arg.key)?;
            Ok(Identity::Software {
                identity: key,
                host: key_arg.host,
                port: key_arg.port,
            })
        } else {
            Err(ClientError::Internal("no identity provided".into()))
        }
    }

    pub fn build(self) -> ClientResult<(Box<dyn SigningIdentity>, String, u16)> {
        match self {
            Identity::Software {
                identity,
                host,
                port,
            } => Ok((Box::new(identity), host, port)),
        }
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
    Create {
        file: PathBuf,
    },
    Get {
        name: String,
        #[arg(short, long, default_value_t = OutputFormat::Shell)]
        format: OutputFormat,
    },
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
    #[clap(flatten)]
    identity: ParamIdentityArg,
}

#[derive(Parser, Debug)]
struct IdentityCommands {
    #[command(subcommand)]
    action: IdentityAction,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let identity = Identity::new(cli.identity)?;
    let (identity, host, port) = identity.build()?;

    let client = Client::new();
    let server_url = format!("http://{host}:{port}");

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
                EnvAction::Create { file } => env_create(&session, &file)?,
                EnvAction::Get { name, format } => {
                    let env = env_get(&session, &name)?;
                    env_print(&env, &format)?;
                }
            };
        }
        Commands::Identity(id_cmd) => {
            let session = request_session(&client, identity.as_ref(), &server_url)?;
            match id_cmd.action {
                IdentityAction::Add(args) => {
                    identity_add(&session, args.role, args.name, args.identity.build()?)?
                }
            }
        }
    };
    Ok(())
}
