use anyhow::{Context, Result, bail};
use axum::{
    body::Body, extract::{FromRequestParts, Request, State}, http::{request::Parts, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}, Json, Router
};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::TcpListener;
use tresor::{
    api::session::SessionRequest,
    config::{self, Config, SrvConfig},
    model::Model,
    srv::session,
};

// Extractor for getting the current timestamp.
pub struct CurrentTime(pub DateTime<Utc>);

impl<S> FromRequestParts<S> for CurrentTime
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(CurrentTime(Utc::now()))
    }
}

// This is the axum handler, which acts as a thin wrapper.
async fn start_session_handler(
    CurrentTime(now): CurrentTime,
    State((cfg, model)): State<(SrvConfig, Model)>,
    req: Request<Body>,
) -> Response {
    match session::start_session(now, &cfg, &model, req).await {
        Ok(encrypted_response) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            encrypted_response,
        )
            .into_response(),
        Err(mut e) => {
            e.sanitize();
            (e.status_code(), Json(e)).into_response()
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct SrvCli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long)]
    config: String,
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

    println!("Loading configuration from {}...", &cli.config);
    let config = config::load(Path::new(&cli.config))
        .with_context(|| format!("failed to load configuration from {}", cli.config))?;
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
        .route("/", get(|| async { "Hello, Tresor!" }))
        .route("/session", post(start_session_handler))
        .with_state((config.srv.config.clone(), model));

    let addr = SocketAddr::from(([127, 0, 0, 1], config.srv.port));
    println!("Listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
