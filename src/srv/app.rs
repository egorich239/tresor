use crate::{config::SrvConfig, model::Model, srv::session::SessionManager};

#[derive(Clone)]
pub struct AppState {
    config: SrvConfig,
    sessions: SessionManager,
    model: Model,
}

impl AppState {
    pub async fn new(config: SrvConfig, model: Model) -> Self {
        Self {
            config,
            sessions: SessionManager::new().await,
            model,
        }
    }

    pub fn config(&self) -> &SrvConfig {
        &self.config
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }
}
