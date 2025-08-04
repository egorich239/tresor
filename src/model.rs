use crate::{
    api::{
        ServerCertificate, ServerIdentityClaim,
        error::{ApiError, ApiResult},
        session::{SessionEncKey, SessionId},
    },
    config::{DataStore, Srv},
    identity::{IdentityRole, SignatureError, SoftwareIdentity, VerifyingIdentity},
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
    SignatureError(#[from] SignatureError),
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
        let rot = cfg.config.sw_identity_rot_period;

        let root = SoftwareIdentity::generate();
        let root_key_path = root.save(&cfg.data.identities_dir())?;
        std::os::unix::fs::symlink(&root_key_path, cfg.data.root_key_symlink())?;
        fs::create_dir(cfg.data.server_cert_dir(&root.verifying_identity()))?;

        let srv = SoftwareIdentity::generate();
        let srv_key_path = srv.save(&cfg.data.identities_dir())?;
        std::os::unix::fs::symlink(&srv_key_path, cfg.data.srv_key_symlink())?;

        ServerCertificate::new(
            ServerIdentityClaim {
                server_pubkey: srv.verifying_identity(),
                issuer_pubkey: root.verifying_identity(),
                issued_at: now,
                expires_at: now + rot,
            },
            &root,
        )?
        .save(&cfg.data.server_cert_dir(&root.verifying_identity()))?;

        Self::_insert_identity(
            &pool,
            now,
            rot,
            "root",
            IdentityRole::Admin,
            &root.verifying_identity(),
        )
        .await?;
        Self::_insert_identity(
            &pool,
            now,
            rot,
            "srv",
            IdentityRole::Server,
            &srv.verifying_identity(),
        )
        .await?;

        pool.close().await;

        Ok(())
    }
}

impl Model {
    async fn _insert_identity(
        pool: &SqlitePool,
        now: DateTime<Utc>,
        rot: Duration,
        name: &str,
        role: IdentityRole,
        identity: &VerifyingIdentity,
    ) -> ModelInitResult<()> {
        sqlx::query(
            "INSERT INTO identities (name, public_key, role, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(name)
        .bind(identity.hex())
        .bind(role.to_string())
        .bind(now.to_rfc3339())
        .bind((now + rot).to_rfc3339())
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn check_identity(
        &self,
        now: DateTime<Utc>,
        key: &VerifyingIdentity,
    ) -> ApiResult<()> {
        sqlx::query(
            "
            SELECT 1
            FROM identities
            WHERE public_key = ?1
              AND compromised_at IS NULL
              AND ?2 BETWEEN approved_at AND COALESCE(expires_at, ?2)
            ",
        )
        .bind(key.hex())
        .bind(now.to_rfc3339())
        .fetch_optional(&self.0.pool)
        .await
        .map_err(|_| ApiError::InvalidIdentity)?
        .ok_or(ApiError::InvalidIdentity)?;
        Ok(())
    }

    pub async fn fetch_server_identity_for(
        &self,
        now: DateTime<Utc>,
        client: &VerifyingIdentity,
    ) -> ApiResult<(SoftwareIdentity, ServerCertificate)> {
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
            let pk = pk.unwrap();
            let cert = ServerCertificate::load(&self.0.data.server_certs_dir(), &pk);
            if cert.is_err() {
                continue;
            }
            let cert = cert.unwrap();
            if cert.check(now, &pk, client).is_err() {
                continue;
            }
            let srv_ident = SoftwareIdentity::load(&self.0.data.identities_dir(), cert.identity());
            if srv_ident.is_err() {
                continue;
            }
            return Ok((srv_ident.unwrap(), cert));
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
        .bind(cli_ident.hex())
        .bind(srv_ident.hex())
        .bind(now.to_rfc3339())
        .bind((now + duration).to_rfc3339())
        .execute(&self.0.pool)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok((session_id, enc_key))
    }
}
