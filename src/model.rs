use crate::{
    api::{error::{ApiError, ApiResult}, session::{SessionEncKey, SessionId}},
    config::{DataStore, Srv},
    identity::{
        Certificate, IdentityError, IdentityIoError, IdentityRole, SoftwareIdentity,
        VerifyingIdentity, VerifyingKeyHex,
    },
};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};
use std::{fs, sync::Arc, time::Duration};
use thiserror::Error;

const DB_SCHEMA: &str = include_str!("../sql/schema.sql");

struct ModelState {
    pool: SqlitePool,
    data: DataStore,
}

#[derive(Clone)]
pub struct Model(Arc<ModelState>);

#[derive(Error, Debug)]
pub enum ModelConnectError {
    #[error(transparent)]
    Sqlite(#[from] sqlx::Error),
}

#[derive(Error, Debug)]
pub enum ModelInitError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Sqlite(#[from] sqlx::Error),

    #[error(transparent)]
    IdentityIo(#[from] IdentityIoError),
}

type ModelInitResult<T> = std::result::Result<T, ModelInitError>;

impl Model {
    pub async fn connect(data: &DataStore) -> Result<Self, ModelConnectError> {
        let pool =
            SqlitePool::connect_with(SqliteConnectOptions::new().filename(data.db_path())).await?;
        Ok(Self(Arc::new(ModelState {
            pool,
            data: data.clone(),
        })))
    }

    /// Initializes the model.
    pub async fn init(cfg: &Srv) -> ModelInitResult<()> {
        let db_path = cfg.data.db_path();
        let pool = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(true),
        )
        .await?;

        // The `sql/schema.sql` file contains multiple SQL statements separated by ';'.
        // We need to execute them one by one.
        for statement in DB_SCHEMA.split(';') {
            if !statement.trim().is_empty() {
                sqlx::query(statement).execute(&pool).await?;
            }
        }

        fs::create_dir(cfg.data.identities_dir())?;
        fs::create_dir(cfg.data.server_certs_dir())?;

        let now = Utc::now();
        let rot = cfg.config.srv_key_rot_interval;

        let root = SoftwareIdentity::create_self_signed(now, rot);
        let root_cert_path = root.save(&cfg.data.identities_dir())?;
        std::os::unix::fs::symlink(&root_cert_path, cfg.data.root_identity_cert_symlink())?;
        fs::create_dir(cfg.data.server_cert_dir(root.verifying_identity()))?;

        let srv = root.create_new_identity(IdentityRole::Server, now, rot);
        let srv_cert_path = srv.save(&cfg.data.identities_dir())?;
        std::os::unix::fs::symlink(&srv_cert_path, cfg.data.srv_identity_cert_symlink())?;
        srv.verifying_identity()
            .save(&cfg.data.server_cert_dir(root.verifying_identity()))?;

        Self::_insert_identity(&pool, "root", root.verifying_identity()).await?;
        Self::_insert_identity(&pool, "srv", srv.verifying_identity()).await?;

        pool.close().await;

        Ok(())
    }
}

impl Model {
    async fn _insert_identity(
        pool: &SqlitePool,
        name: &str,
        identity: &VerifyingIdentity,
    ) -> ModelInitResult<()> {
        let payload = identity.certificate().payload();
        sqlx::query(
            "INSERT INTO identities (name, public_key, role, approved_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(name)
        .bind(identity.key_hex())
        .bind(payload.subject_role.to_string())
        .bind(payload.issued_at.to_rfc3339())
        .bind(payload.expires_at.to_rfc3339())
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn fetch_identity(
        &self,
        now: DateTime<Utc>,
        key: &VerifyingKeyHex,
    ) -> ApiResult<VerifyingIdentity> {
        let db_check = async {
            let row = sqlx::query("SELECT compromised_at FROM identities WHERE public_key = ?1")
                .bind(key.hex())
                .fetch_optional(&self.0.pool)
                .await
                .map_err(|_| ApiError::InvalidIdentity)?
                .ok_or(ApiError::InvalidIdentity)?;

            let compromised_at: Option<String> = row.get("compromised_at");
            match compromised_at {
                Some(_) => Err(ApiError::InvalidIdentity),
                None => Ok(()),
            }
        };

        let file_load = async {
            let key = key.clone();
            let state = self.0.clone();
            tokio::task::spawn_blocking(move || {
                VerifyingIdentity::load(&state.data.identities_dir(), key.key(), now)
            })
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map_err(|e| match e {
                IdentityIoError::IdentityError(IdentityError::CertificateExpired { .. }) => {
                    ApiError::InvalidIdentity
                }
                _ => ApiError::Internal(e.to_string()),
            })
        };

        let (_db_result, file_result) = tokio::try_join!(db_check, file_load)?;

        Ok(file_result)
    }

    pub async fn fetch_server_identity_for(
        &self,
        now: DateTime<Utc>,
        client: &VerifyingIdentity,
    ) -> ApiResult<(SoftwareIdentity, Certificate)> {
        let server_identities = sqlx::query(
            "SELECT public_key FROM identities WHERE role = 'server' AND compromised_at IS NULL ORDER BY id DESC",
        )
        .fetch_all(&self.0.pool)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        for row in server_identities {
            let pk: String = row.get("public_key");
            let pk = pk
                .as_str()
                .try_into()
                .map_err(|_| ApiError::Internal("invalid public_key".into()));
            if pk.is_err() {
                continue;
            }
            let pk: VerifyingKeyHex = pk.unwrap();

            let srv_identity =
                VerifyingIdentity::load(&self.0.data.server_cert_dir(client), pk.key(), now);
            if srv_identity.is_err() {
                continue;
            }
            let srv_identity = srv_identity.unwrap();

            let signing_identity =
                SoftwareIdentity::load(&self.0.data.identities_dir(), &srv_identity);

            if let Ok(signing_identity) = signing_identity {
                return Ok((signing_identity, srv_identity.certificate().clone()));
            }
        }

        Err(ApiError::InvalidServerIdentity)
    }

    pub async fn register_session(
        &self,
        now: DateTime<Utc>,
        duration: Duration,
        cli_ident: &VerifyingIdentity,
        srv_ident: &VerifyingIdentity,
    ) -> ApiResult<(SessionId, SessionEncKey)> {
        let session_id = SessionId::new();
        let enc_key = SessionEncKey::generate();

        sqlx::query(
            "INSERT INTO sessions (session_id, enc_key, client_identity, server_identity, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(session_id.to_hex())
        .bind(enc_key.to_hex())
        .bind(cli_ident.key_hex())
        .bind(srv_ident.key_hex())
        .bind(now.to_rfc3339())
        .bind((now + duration).to_rfc3339())
        .execute(&self.0.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(f) if f.kind() == sqlx::error::ErrorKind::UniqueViolation => { 
                ApiError::TransientError
            }
            _ => ApiError::Internal(e.to_string()),
        })?;

        Ok((session_id, enc_key))
    }
}

