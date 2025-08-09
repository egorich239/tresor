use crate::{
    api::{
        ServerCertificate, ServerIdentityClaim,
        env::{Env, EnvResponse, Envvar},
        error::{ApiError, ApiResult},
        identity::IdentityResponse,
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

    fn _key_file(data: &DataStore, identity: &VerifyingIdentity) -> PathBuf {
        data.identities_dir()
            .join(DataStore::file_by_identity(identity, "key"))
    }
}

pub struct ModelTx<'a> {
    tx: Transaction<'a, Sqlite>,
    now: DateTime<Utc>,
    data: DataStore,
}

#[derive(Debug, Clone)]
pub struct ClientIdentity(i32, VerifyingIdentity, IdentityRole);

#[derive(Debug, Clone)]
pub struct ServerIdentity(i32, SoftwareIdentity, ServerCertificate);

#[derive(Debug, Clone)]
pub struct TxSession(i32);

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

    pub async fn tx(&self, now: DateTime<Utc>) -> ApiResult<ModelTx<'_>> {
        let tx = self.0.pool.begin().await.map_err(ApiError::internal)?;
        Ok(ModelTx {
            tx,
            now,
            data: self.0.data.clone(),
        })
    }
}

impl ModelTx<'_> {
    pub async fn commit(self) -> ApiResult<()> {
        self.tx.commit().await.map_err(ApiError::internal)?;
        Ok(())
    }

    pub async fn get_identity(&mut self, key: &VerifyingIdentity) -> ApiResult<ClientIdentity> {
        let row = sqlx::query(
            "
                SELECT id, role
                FROM identities
                WHERE public_key = ?1
                AND compromised_at IS NULL
                AND ?2 BETWEEN created_at AND COALESCE(expires_at, ?2)",
        )
        .bind(key.hex())
        .bind(self.now.to_rfc3339())
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(|_| ApiError::InvalidIdentity)?
        .ok_or(ApiError::InvalidIdentity)?;
        let id = row.get("id");
        let role: String = row.get("role");
        Ok(ClientIdentity(
            id,
            key.clone(),
            role.as_str().try_into().map_err(ApiError::internal)?,
        ))
    }

    pub async fn get_server_identity_claim(
        &mut self,
        issuer: &VerifyingIdentity,
    ) -> ApiResult<ServerIdentityClaim> {
        let row = sqlx::query(
            "
            SELECT public_key, created_at, expires_at
            FROM identities
            WHERE role = 'server' AND compromised_at IS NULL
            ORDER BY id DESC
            LIMIT 1",
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(ApiError::internal)?
        .ok_or(ApiError::internal("no server identity found"))?;

        let key: String = row.get("public_key");
        let key = key.as_str().try_into().map_err(ApiError::internal)?;
        let created_at: DateTime<Utc> = row
            .get::<String, _>("created_at")
            .parse()
            .map_err(ApiError::internal)?;
        let expires_at: DateTime<Utc> = row
            .get::<String, _>("expires_at")
            .parse()
            .map_err(ApiError::internal)?;

        Ok(ServerIdentityClaim {
            server_pubkey: key,
            issuer_pubkey: issuer.clone(),
            issued_at: created_at,
            expires_at,
        })
    }

    pub async fn get_server_identity_for(
        &mut self,
        client: &ClientIdentity,
    ) -> ApiResult<ServerIdentity> {
        let server_identities = sqlx::query(
            "
            SELECT id, public_key
            FROM identities
            WHERE role = 'server' AND compromised_at IS NULL
            ORDER BY id DESC",
        )
        .fetch_all(&mut *self.tx)
        .await
        .map_err(ApiError::internal)?;

        let certs_dir = self.data.server_cert_dir(&client.1);
        for row in server_identities {
            let pk: String = row.get("public_key");
            let pk = pk
                .as_str()
                .try_into()
                .map_err(|_| ApiError::internal("invalid public_key"));
            if pk.is_err() {
                continue;
            }
            let pk = pk.unwrap();
            let cert = ServerCertificate::load(&certs_dir, &pk);
            if cert.is_err() {
                continue;
            }
            let cert = cert.unwrap();
            if cert.check(self.now, &pk, &client.1).is_err() {
                continue;
            }
            let file = Model::_key_file(&self.data, cert.identity());
            let srv_ident = SoftwareIdentity::load(&file);
            if srv_ident.is_err() {
                continue;
            }
            let srv_ident = srv_ident.unwrap();
            if srv_ident.verifying_identity() != pk {
                continue;
            }
            return Ok(ServerIdentity(row.get("id"), srv_ident, cert));
        }

        Err(ApiError::InvalidServerIdentity)
    }

    pub async fn register_session(
        &mut self,
        duration: Duration,
        nonce: Nonce,
        cli_ident: &ClientIdentity,
        srv_ident: &ServerIdentity,
    ) -> ApiResult<(SessionId, SessionEncKey, IdentityRole)> {
        let session_id = SessionId::generate();
        let enc_key = SessionEncKey::generate();

        sqlx::query(
            "INSERT INTO sessions
                (session_id, nonce, client_id, server_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(session_id.to_hex())
        .bind(nonce.to_hex())
        .bind(cli_ident.0)
        .bind(srv_ident.0)
        .bind(self.now.to_rfc3339())
        .bind((self.now + duration).to_rfc3339())
        .execute(&mut *self.tx)
        .await
        .map_err(ApiError::internal)?;
        Ok((session_id, enc_key, cli_ident.2))
    }

    pub async fn get_session(&mut self, session_id: &SessionId) -> ApiResult<TxSession> {
        let row = sqlx::query("SELECT id FROM sessions WHERE session_id = ?1")
            .bind(session_id.to_hex())
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(ApiError::internal)?
            .ok_or(ApiError::Unauthorized)?;
        Ok(TxSession(row.get("id")))
    }

    pub async fn secret_add(
        &mut self,
        session: &TxSession,
        name: &str,
        value: &str,
        description: &str,
    ) -> ApiResult<SecretResponse> {
        if name.is_empty() || description.is_empty() {
            return Err(ApiError::BadRequest);
        }

        let result = sqlx::query(
            "
            INSERT INTO secret_keys (key, description, created_session_id)
            VALUES (?1, ?2, ?3)
            RETURNING id
            ",
        )
        .bind(name)
        .bind(description)
        .bind(session.0)
        .fetch_optional(&mut *self.tx)
        .await;
        let key_id: i32 = match result {
            Ok(row) => row
                .ok_or(ApiError::internal("failed to insert secret key"))?
                .get("id"),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Ok(SecretResponse::KeyExists);
            }
            Err(e) => {
                return Err(ApiError::internal(e));
            }
        };

        sqlx::query(
            "INSERT INTO secrets (key_id, value, created_session_id)
             VALUES (?1, ?2, ?3)",
        )
        .bind(key_id)
        .bind(value)
        .bind(session.0)
        .execute(&mut *self.tx)
        .await
        .map_err(ApiError::internal)?;
        Ok(SecretResponse::Success)
    }

    pub async fn secret_update(
        &mut self,
        session: &TxSession,
        name: &str,
        value: &str,
    ) -> ApiResult<SecretResponse> {
        let result = sqlx::query(
            "
            INSERT INTO secrets (key_id, value, created_session_id)
            VALUES
            (
            (SELECT id FROM secret_keys WHERE key = ?1 AND deleted_session_id IS NULL),
            ?2, ?3)
            ",
        )
        .bind(name)
        .bind(value)
        .bind(session.0)
        .execute(&mut *self.tx)
        .await;
        match result {
            Ok(_) => Ok(SecretResponse::Success),
            Err(sqlx::Error::Database(e)) if e.is_foreign_key_violation() => {
                Ok(SecretResponse::KeyNotFound)
            }
            Err(e) => Err(ApiError::internal(e)),
        }
    }

    pub async fn secret_delete(
        &mut self,
        session: &TxSession,
        name: &str,
    ) -> ApiResult<SecretResponse> {
        let result = sqlx::query(
            "
            UPDATE secret_keys
            SET
                deleted_session_id = ?1,
                deleted_at = ?2
            WHERE key = ?3 AND deleted_session_id IS NULL",
        )
        .bind(session.0)
        .bind(self.now.to_rfc3339())
        .bind(name)
        .execute(&mut *self.tx)
        .await
        .map_err(ApiError::internal)?;
        match result.rows_affected() {
            0 => Ok(SecretResponse::KeyNotFound),
            _ => Ok(SecretResponse::Success),
        }
    }

    pub async fn identity_add(
        &mut self,
        session: &TxSession,
        name: &str,
        key: &VerifyingIdentity,
        role: IdentityRole,
    ) -> ApiResult<IdentityResponse> {
        if name.is_empty() || role == IdentityRole::Server {
            return Err(ApiError::BadRequest);
        }
        let result = sqlx::query(
            "
            INSERT INTO identities (name, public_key, role, created_session_id)
            VALUES (?1, ?2, ?3, ?4)
            ",
        )
        .bind(name)
        .bind(key.hex())
        .bind(role.to_string())
        .bind(session.0)
        .execute(&mut *self.tx)
        .await;
        match result {
            Ok(_) => Ok(IdentityResponse::Success),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Ok(IdentityResponse::AlreadyExists)
            }
            Err(e) => Err(ApiError::internal(e)),
        }
    }

    pub async fn env_create(
        &mut self,
        session: &TxSession,
        env: &str,
        pairs: &[Envvar],
    ) -> ApiResult<EnvResponse> {
        if env.is_empty() {
            return Err(ApiError::BadRequest);
        }

        let result = sqlx::query(
            "
            INSERT INTO envs (name, created_session_id)
            VALUES (?1, ?2)
            RETURNING id
            ",
        )
        .bind(env)
        .bind(session.0)
        .fetch_optional(&mut *self.tx)
        .await;

        let env_id: i32 = match result {
            Ok(row) => row
                .ok_or(ApiError::internal("failed to insert env"))?
                .get("id"),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Ok(EnvResponse::EnvExists);
            }
            Err(e) => return Err(ApiError::internal(e)),
        };

        for pair in pairs {
            let result = sqlx::query(
                "
                INSERT INTO envvars (env_id, key_id, envvar, created_session_id)
                SELECT ?1, id, ?2, ?3
                FROM secret_keys
                WHERE key = ?4 AND deleted_at IS NULL
                ",
            )
            .bind(env_id)
            .bind(&pair.var)
            .bind(session.0)
            .bind(&pair.key)
            .execute(&mut *self.tx)
            .await
            .map_err(ApiError::internal)?;

            if result.rows_affected() == 0 {
                return Err(ApiError::BadRequest);
            }
        }

        Ok(EnvResponse::Success)
    }

    pub async fn env_get(&mut self, env: &str) -> ApiResult<Env> {
        let mut envvars: Vec<_> = sqlx::query(
            "
            SELECT ev.envvar envvar, s2.value value
            FROM envvars ev
            INNER JOIN
                (
                SELECT ev.key_id key_id, MAX(s.id) secret_id
                FROM envvars ev
                INNER JOIN envs e
                ON ev.env_id = e.id
                INNER JOIN secrets s
                ON ev.key_id = s.key_id
                WHERE e.name = ?1 AND e.deleted_at IS NULL
                ) s1
            ON ev.key_id = s1.key_id
            INNER JOIN secrets s2
            ON s1.secret_id = s2.id",
        )
        .bind(env)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(|row| Envvar {
            var: row.get("envvar"),
            key: row.get("value"),
        })
        .collect();
        envvars.sort_by_key(|e| e.var.clone());
        Ok(envvars)
    }
}

impl ServerIdentity {
    pub fn identity(&self) -> &SoftwareIdentity {
        &self.1
    }

    pub fn certificate(&self) -> &ServerCertificate {
        &self.2
    }
}
