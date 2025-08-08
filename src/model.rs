use crate::{
    api::{
        ServerCertificate, ServerIdentityClaim,
        error::{ApiError, ApiResult},
        secret::SecretResponse,
        session::{Nonce, SessionEncKey, SessionId},
    },
    config::{DataStore, Srv},
    identity::{IdentityRole, SignatureError, SoftwareIdentity, VerifyingIdentity},
};
use chrono::{DateTime, Utc};
use sqlx::{Row, Sqlite, SqlitePool, Transaction, sqlite::SqliteConnectOptions};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};
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
        let data = data.clone();
        Ok(Self(Arc::new(ModelState { pool, data })))
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
        let root_key_path = Self::_key_file(&cfg.data, &root.verifying_identity());
        root.save(&root_key_path)?;
        std::os::unix::fs::symlink(&root_key_path, cfg.data.root_key_symlink())?;
        fs::create_dir(cfg.data.server_cert_dir(&root.verifying_identity()))?;

        let srv = SoftwareIdentity::generate();
        let srv_key_path = Self::_key_file(&cfg.data, &srv.verifying_identity());
        srv.save(&srv_key_path)?;
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
              AND ?2 BETWEEN created_at AND COALESCE(expires_at, ?2)
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

        let certs_dir = self.0.data.server_cert_dir(client);
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
            let cert = ServerCertificate::load(&certs_dir, &pk);
            if cert.is_err() {
                continue;
            }
            let cert = cert.unwrap();
            if cert.check(now, &pk, client).is_err() {
                continue;
            }
            let file = Self::_key_file(&self.0.data, cert.identity());
            let srv_ident = SoftwareIdentity::load(&file);
            if srv_ident.is_err() {
                continue;
            }
            let srv_ident = srv_ident.unwrap();
            if srv_ident.verifying_identity() != pk {
                continue;
            }
            return Ok((srv_ident, cert));
        }

        Err(ApiError::InvalidServerIdentity)
    }

    pub async fn register_session(
        &self,
        now: DateTime<Utc>,
        duration: Duration,
        nonce: Nonce,
        cli_ident: &VerifyingIdentity,
        srv_ident: &VerifyingIdentity,
    ) -> ApiResult<(SessionId, SessionEncKey, IdentityRole)> {
        let session_id = SessionId::generate();
        let enc_key = SessionEncKey::generate();

        let mut tx = self.0.pool.begin().await.map_err(Self::_internal)?;

        sqlx::query(
            "INSERT INTO sessions (session_id, nonce, client_id, server_id, created_at, expires_at)
             VALUES (
                ?1, 
                ?2,
                (SELECT id FROM identities WHERE public_key = ?3 AND role IN ('admin', 'reader')),
                (SELECT id FROM identities WHERE public_key = ?4 AND role = 'server'),
                ?5, ?6)",
        )
        .bind(session_id.to_hex())
        .bind(nonce.to_hex())
        .bind(cli_ident.hex())
        .bind(srv_ident.hex())
        .bind(now.to_rfc3339())
        .bind((now + duration).to_rfc3339())
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::_conflict_as(e, ApiError::BadRequest))?;

        let role = sqlx::query("SELECT role FROM identities WHERE public_key = ?1")
            .bind(cli_ident.hex())
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::_internal)?
            .ok_or(ApiError::Unauthorized)?;
        let role: String = role.get("role");
        let role: IdentityRole = role
            .as_str()
            .try_into()
            .map_err(|_| ApiError::internal("invalid role value"))?;
        tx.commit().await.map_err(Self::_internal)?;
        Ok((session_id, enc_key, role))
    }

    pub async fn secret_add(
        &self,
        session_id: &SessionId,
        name: &str,
        value: &str,
        description: &str,
    ) -> ApiResult<SecretResponse> {
        if description.is_empty() {
            return Err(ApiError::BadRequest);
        }

        let (mut tx, state) = self._secret_query_prelude(name).await?;
        if state == SecretState::Exists {
            return Ok(SecretResponse::KeyExists);
        }

        sqlx::query(
            "INSERT INTO secrets (key, value, description, created_session_id)
             VALUES (?1, ?2, ?3, 
                    (SELECT id FROM sessions WHERE session_id = ?4))",
        )
        .bind(name)
        .bind(value)
        .bind(description)
        .bind(session_id.to_hex())
        .execute(&mut *tx)
        .await
        .map_err(Self::_internal)?;
        tx.commit().await.map_err(Self::_internal)?;
        Ok(SecretResponse::Success)
    }

    pub async fn secret_update(
        &self,
        session_id: &SessionId,
        name: &str,
        value: &str,
    ) -> ApiResult<SecretResponse> {
        let (mut tx, state) = self._secret_query_prelude(name).await?;
        if state != SecretState::Exists {
            return Ok(SecretResponse::KeyNotFound);
        }

        sqlx::query(
            "INSERT INTO secrets (key, value, created_session_id) VALUES (?1, ?2, 
                    (SELECT id FROM sessions WHERE session_id = ?3))",
        )
        .bind(name)
        .bind(value)
        .bind(session_id.to_hex())
        .execute(&mut *tx)
        .await
        .map_err(Self::_internal)?;
        tx.commit().await.map_err(Self::_internal)?;
        Ok(SecretResponse::Success)
    }

    pub async fn secret_delete(
        &self,
        session_id: &SessionId,
        name: &str,
    ) -> ApiResult<SecretResponse> {
        let (mut tx, state) = self._secret_query_prelude(name).await?;
        if state != SecretState::Exists {
            return Ok(SecretResponse::KeyNotFound);
        }

        sqlx::query(
            "INSERT INTO secrets (key, created_session_id) VALUES (?1, 
                    (SELECT id FROM sessions WHERE session_id = ?2))",
        )
        .bind(name)
        .bind(session_id.to_hex())
        .execute(&mut *tx)
        .await
        .map_err(Self::_internal)?;
        tx.commit().await.map_err(Self::_internal)?;
        Ok(SecretResponse::Success)
    }

    async fn _secret_query_prelude(
        &self,
        name: &str,
    ) -> ApiResult<(Transaction<'_, Sqlite>, SecretState)> {
        if name.is_empty() {
            return Err(ApiError::BadRequest);
        }

        let mut tx = self.0.pool.begin().await.map_err(Self::_internal)?;
        let row = sqlx::query("SELECT value FROM secrets WHERE key = ?1 ORDER BY id DESC LIMIT 1")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        match row {
            None => Ok((tx, SecretState::NotExists)),
            Some(row) => {
                let value: Option<String> = row.get("value");
                match value {
                    None => Ok((tx, SecretState::Deleted)),
                    Some(_) => Ok((tx, SecretState::Exists)),
                }
            }
        }
    }

    fn _conflict_as(e: sqlx::Error, err: ApiError) -> ApiError {
        if let sqlx::Error::Database(e) = &e {
            if e.is_unique_violation() {
                return err;
            }
        }
        ApiError::Internal(e.to_string())
    }

    fn _key_file(data: &DataStore, identity: &VerifyingIdentity) -> PathBuf {
        data.identities_dir()
            .join(DataStore::file_by_identity(identity, "key"))
    }

    fn _internal(e: sqlx::Error) -> ApiError {
        ApiError::Internal(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretState {
    NotExists,
    Exists,
    Deleted,
}
