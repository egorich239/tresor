use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Args, Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tresor::{
    config::Config,
    model::Model,
    srv::{
        AppState, CurrentTime, claim_handler, env_handler, get_handler, identity_handler,
        publish_handler, secret_handler, start_session,
    },
};

// This is the axum handler, which acts as a thin wrapper.
async fn start_session_handler(
    CurrentTime(now): CurrentTime,
    State(app): State<AppState>,
    req: Request<Body>,
) -> Response {
    start_session(now, &app, req).await.into_response()
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct SrvCli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long)]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server (default).
    Run,
    /// Initialize a new Tresor database.
    Init(InitArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Force re-initialization, overwriting existing data.
    #[arg(short, long)]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = SrvCli::parse();
    let command = cli.command.unwrap_or(Commands::Run);

    println!("Loading configuration from {:?}...", cli.config);
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load configuration from {:?}", cli.config))?;
    println!("Configuration loaded successfully.");

    match command {
        Commands::Init(args) => cmd_init(&config, args).await?,
        Commands::Run => cmd_run(&config).await?,
    }

    Ok(())
}

async fn cmd_init(config: &Config, args: InitArgs) -> Result<()> {
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
    Model::init(&config.srv)
        .await
        .context("failed to initialize model")?;
    println!("Model initialized successfully.");

    Ok(())
}

async fn cmd_run(config: &Config) -> Result<()> {
    let model = Model::connect(&config.srv.data).await?;

    let app = Router::new()
        .route("/secret", post(secret_handler))
        .route("/env", post(env_handler))
        .route("/identity", post(identity_handler))
        .route("/publish", post(publish_handler))
        .route("/get/{endpoint}", get(get_handler))
        .route("/claim", post(claim_handler))
        .route("/session", post(start_session_handler))
        .with_state(AppState::new(config.srv.config.clone(), model).await);

    let addr = SocketAddr::from(([127, 0, 0, 1], config.srv.port));
    println!("Listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
