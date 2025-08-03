use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use clap::Parser;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tresor::{
    api::session::{self, SessionRequest},
    config::{self, SrvConfig},
    model::Model,
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
    Json(req): Json<SessionRequest>,
) -> Response {
    match session::start_session(now, &cfg, &model, req).await {
        Ok(encrypted_response) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            encrypted_response,
        )
            .into_response(),
        Err(e) => e.into(),
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct SrvCli {
    #[arg(short, long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = SrvCli::parse();

    println!("Loading configuration from {}...", &cli.config);
    let config = config::load(cli.config.as_ref())
        .with_context(|| format!("failed to load configuration from {}", &cli.config))?;
    println!("Configuration loaded successfully.");

    let model = Model::connect(&config.srv.data).await?;

    let app = Router::new()
        .route("/", get(|| async { "Hello, Tresor!" }))
        .route("/session", post(start_session_handler))
        .with_state((config.srv.config.clone(), model));

    let addr = SocketAddr::from(([127, 0, 0, 1], config.srv.port));
    println!("listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
