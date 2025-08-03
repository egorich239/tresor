use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::Path;
use tokio::runtime;
use tresor::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, group = "mode")]
    config: Option<String>,

    #[arg(short, long, group = "mode")]
    server: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Tresor database.
    Init(InitArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Force re-initialization, overwriting existing data.
    #[arg(short, long)]
    force: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => {
            let rt = runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_init(cli.config, args))?;
        }
    }

    Ok(())
}

async fn cmd_init(config_path: Option<String>, args: InitArgs) -> Result<()> {
    let config_path = config_path.context("the `init` command requires the --config flag")?;

    println!("Loading configuration from {}...", &config_path);
    let config = config::load(Path::new(&config_path))
        .with_context(|| format!("failed to load configuration from {config_path}"))?;
    println!("Configuration loaded successfully.");

    let data_dir = config.srv.data.path();
    if data_dir.exists() {
        if args.force {
            println!(
                "--force flag set. Removing existing data directory at {}...",
                data_dir.display()
            );
            std::fs::remove_dir_all(data_dir).with_context(|| {
                format!(
                    "failed to remove existing data directory at {}",
                    data_dir.display()
                )
            })?;
            println!("Data directory removed.");
        } else {
            bail!(
                "data directory {} already exists. Use --force to overwrite.",
                data_dir.display()
            );
        }
    }

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data directory at {}", data_dir.display()))?;

    println!("Initializing model at {data_dir:?}...");
    model::Model::init(&config.srv)
        .await
        .context("failed to initialize model")?;
    println!("Model initialized successfully.");

    Ok(())
}
