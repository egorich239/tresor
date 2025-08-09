use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha512};
use tokio::sync::RwLock;

use crate::{
    api::{ApiError, ApiResult, PublishRequest, PublishResponse, SessionEncKey},
    enc::AesSession,
    srv::{
        AppState,
        session::{CurrentTime, SessionQuery, SessionState},
    },
};

type PublishStoreState = Arc<RwLock<HashMap<String, (Vec<u8>, DateTime<Utc>)>>>;
#[derive(Clone)]
pub struct PublishStore(PublishStoreState);

impl PublishStore {
    pub async fn new() -> Self {
        let state = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(Self::_gc_loop(state.clone(), Duration::from_secs(30)));
        Self(state)
    }

    pub async fn put(&self, hash: String, data: Vec<u8>, deadline: DateTime<Utc>) {
        self.0.write().await.insert(hash, (data, deadline));
    }

    pub async fn get(&self, hash: &str) -> Option<Vec<u8>> {
        let map = self.0.read().await;
        map.get(hash).map(|(data, _)| data.clone())
    }

    async fn _gc_loop(state: PublishStoreState, interval: Duration) {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            Self::_gc(state.clone(), Utc::now()).await;
        }
    }

    async fn _gc(state: PublishStoreState, now: DateTime<Utc>) {
        let mut map = state.write().await;
        map.retain(|_, (_, deadline)| *deadline > now);
    }
}

pub async fn publish_handler(
    State(app): State<AppState>,
    CurrentTime(now): CurrentTime,
    SessionQuery { session, query }: SessionQuery<PublishRequest, 'r'>,
) -> impl IntoResponse {
    let session = session.read().await;
    session
        .response(_publish_handler(&app, &session, query, now).await)
        .await
}

async fn _publish_handler(
    app: &AppState,
    session: &SessionState,
    query: PublishRequest,
    now: DateTime<Utc>,
) -> ApiResult<PublishResponse> {
    let mut tx = app.model().tx(now).await?;
    let env = tx.env_get(&query.env).await?;
    tx.commit().await?;

    let envvars = serde_json::to_vec(&env).map_err(|_| ApiError::Internal)?;
    let key = SessionEncKey::generate();
    let sid = session.session_id().clone();
    let aes = AesSession::new(key.clone(), sid);
    let ciphertext = aes.encrypt(&envvars);

    let endpoint = hex::encode(Sha512::digest(ciphertext.ciphertext()));
    let deadline = now + Duration::from_secs(60);
    app.publish()
        .put(endpoint.clone(), ciphertext.ciphertext().to_vec(), deadline)
        .await;
    Ok(PublishResponse {
        key,
        nonce: ciphertext.nonce(),
        endpoint,
    })
}

pub async fn get_handler(
    State(app): State<AppState>,
    Path(endpoint): Path<String>,
) -> impl IntoResponse {
    if let Some(bytes) = app.publish().get(&endpoint).await {
        (axum::http::StatusCode::OK, bytes)
    } else {
        (axum::http::StatusCode::NOT_FOUND, Vec::new())
    }
}
