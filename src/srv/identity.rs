use axum::{extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};

use crate::{
    api::{IdentityRequest, IdentityResponse, ServerCertificate, TransportResult},
    identity::IdentityRole,
    model::{ModelTx, TxSession},
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery, SessionState},
    },
};

pub async fn identity_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<IdentityRequest, 'a'>,
) -> impl IntoResponse {
    let session = session.read().await;
    session
        .response(_identity_handler(&app, &session, query, now).await)
        .await
}

async fn _identity_handler(
    app: &AppState,
    session: &SessionState,
    req: IdentityRequest,
    now: DateTime<Utc>,
) -> TransportResult<IdentityResponse> {
    let mut tx = app.model().tx(now).await?;
    let session_id = tx.get_session(session.session_id()).await?;
    let res = match req {
        IdentityRequest::Add {
            name,
            role,
            certificate,
        } => _identity_add(&mut tx, &session_id, &name, role, &certificate).await?,
    };
    tx.commit().await?;
    Ok(res)
}

async fn _identity_add(
    tx: &mut ModelTx<'_>,
    session_id: &TxSession,
    name: &str,
    role: IdentityRole,
    certificate: &ServerCertificate,
) -> TransportResult<IdentityResponse> {
    tx.identity_add(session_id, name, certificate, role).await
}
