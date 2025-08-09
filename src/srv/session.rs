use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Request, rejection::JsonRejection},
    http::request::Parts,
};
use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::RwLock;

use crate::{
    api::{
        ApiError, ApiResult, SessionEncKey, SessionId, SessionRequest, SessionResponsePayload,
        SignedMessage, VerifyStatusApiExt,
    },
    enc::{AesCiphertextRecv, AesNonce, AesSession},
    identity::IdentityRole,
    srv::AppState,
};

pub async fn start_session(
    now: DateTime<Utc>,
    state: &AppState,
    req: Result<Json<SessionRequest>, JsonRejection>,
) -> ApiResult<Vec<u8>> {
    let mut tx = state.model().tx(now).await?;
    let cfg = state.config();
    let Json(req) = req.map_err(|_| ApiError::BadRequest)?;
    let identity = req.payload().identity.clone();
    let client_id = tx.get_identity(&identity).await?;
    req.verify(&identity).to_api_result()?;
    let srv_ident = tx.get_server_identity_for(&client_id).await?;

    let deadline = now + cfg.max_session_duration;
    let (sid, enc_key, role) = tx
        .register_session(
            cfg.max_session_duration,
            req.payload().nonce.clone(),
            &client_id,
            &srv_ident,
        )
        .await?;

    state
        .sessions()
        .insert(sid.clone(), enc_key.clone(), deadline, role)
        .await;

    let response_payload = SessionResponsePayload {
        nonce: req.payload().nonce.clone(),
        session_id: sid,
        certificate: srv_ident.certificate().clone(),
        enc_key,
    };

    let response = SignedMessage::new(response_payload, srv_ident.identity())
        .map_err(|_| ApiError::Internal)?;
    let bytes = serde_json::to_vec(&response).map_err(|_| ApiError::Internal)?;
    tx.commit().await?;

    Ok(req.payload().recepient.encrypt(&bytes))
}

#[derive(Clone)]
pub struct SessionManager(Arc<SessionManagerState>);

struct SessionManagerState {
    sessions: RwLock<HashMap<SessionId, Arc<RwLock<SessionState>>>>,
}

#[derive(Debug)]
pub struct SessionState {
    aes_session: AesSession,
    deadline: DateTime<Utc>,
    nonces: HashSet<AesNonce>,
    client_role: IdentityRole,
}

impl SessionState {
    pub fn session_id(&self) -> &SessionId {
        self.aes_session.session_id()
    }

    pub fn client_role(&self) -> IdentityRole {
        self.client_role
    }

    pub async fn response<R: Serialize>(
        &self,
        res: ApiResult<R>,
    ) -> (axum::http::StatusCode, Vec<u8>) {
        match res {
            Ok(response) => self._ok(response).await,
            Err(e) => self._err(e),
        }
    }

    async fn _ok<R: Serialize>(&self, response: R) -> (axum::http::StatusCode, Vec<u8>) {
        match serde_json::to_vec(&response).map_err(|_| ApiError::Internal) {
            Ok(response) => {
                let enc: Vec<u8> = self.aes_session.encrypt(&response).into();
                (axum::http::StatusCode::OK, enc)
            }
            Err(e) => self._err(e),
        }
    }

    fn _err(&self, e: ApiError) -> (axum::http::StatusCode, Vec<u8>) {
        (e.status_code(), serde_json::to_vec(&e).unwrap())
    }
}

impl SessionManager {
    pub async fn new() -> Self {
        let manager = Self(Arc::new(SessionManagerState {
            sessions: RwLock::new(HashMap::new()),
        }));
        manager.start_gc_loop().await;
        manager
    }

    pub async fn insert(
        &self,
        session_id: SessionId,
        enc_key: SessionEncKey,
        deadline: DateTime<Utc>,
        client_role: IdentityRole,
    ) {
        self.0.sessions.write().await.insert(
            session_id.clone(),
            Arc::new(RwLock::new(SessionState {
                aes_session: AesSession::new(enc_key.clone(), session_id.clone()),
                deadline,
                client_role,
                nonces: HashSet::new(),
            })),
        );
    }

    pub async fn get_query<Q: DeserializeOwned + Debug>(
        &self,
        now: DateTime<Utc>,
        parts: &Parts,
        body: &[u8],
        required_role: IdentityRole,
    ) -> ApiResult<(Arc<RwLock<SessionState>>, Q)> {
        let session_id = parts
            .headers
            .get("X-Tresor-Session-Id")
            .ok_or(ApiError::Unauthorized)?
            .to_str()
            .map_err(|_| ApiError::Unauthorized)?;
        let session_id = session_id.try_into().map_err(|_| ApiError::Unauthorized)?;

        let sessions = self.0.sessions.read().await;
        let session_ptr = sessions.get(&session_id).ok_or(ApiError::Unauthorized)?;

        let mut session = session_ptr.write().await;
        let ciphertext: AesCiphertextRecv = body.try_into().map_err(|_| ApiError::BadRequest)?;
        if session.deadline < now
            || session.client_role != required_role
            || !session.nonces.insert(ciphertext.nonce())
        {
            return Err(ApiError::Unauthorized);
        }

        let query = session
            .aes_session
            .decrypt(ciphertext)
            .ok_or(ApiError::Unauthorized)?;
        let query = serde_json::from_slice(&query).map_err(|_| ApiError::BadRequest)?;
        Ok((session_ptr.clone(), query))
    }

    async fn start_gc_loop(&self) {
        let state = self.0.clone();
        tokio::spawn(async move {
            loop {
                Self::gc(state.clone()).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    async fn gc(state: Arc<SessionManagerState>) {
        let now = Utc::now();
        let mut sessions = state.sessions.write().await;
        let session_ids: Vec<_> = stream::iter(sessions.iter())
            .filter_map(|(session_id, session)| async {
                let session = session.read().await;
                match session.deadline < now {
                    true => Some(session_id.clone()),
                    false => None,
                }
            })
            .collect()
            .await;
        for id in session_ids {
            sessions.remove(&id);
        }
    }
}

#[derive(Debug, Clone)]
pub struct CurrentTime(pub DateTime<Utc>);

impl<S> FromRequestParts<S> for CurrentTime
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let time = parts
            .extensions
            .get_or_insert_with(|| CurrentTime(Utc::now()));
        Ok(time.clone())
    }
}

pub struct SessionQuery<Q: DeserializeOwned, const R: char> {
    pub session: Arc<RwLock<SessionState>>,
    pub query: Q,
}

impl<Q: DeserializeOwned + Debug, const R: char> FromRequest<AppState> for SessionQuery<Q, R> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|_| ApiError::BadRequest)?;
        let now: &CurrentTime = parts.extensions.get().ok_or(ApiError::Internal)?;
        let (session_ptr, query) = state
            .sessions()
            .get_query(now.0, &parts, &body, R.into())
            .await?;
        Ok(SessionQuery {
            session: session_ptr,
            query,
        })
    }
}
