use std::{collections::HashMap, sync::Mutex};

pub static ACTIVE_RESET_SESSION: Mutex<Option<ActiveResetSession>> = Mutex::new(None);

#[derive(Clone)]
pub struct ActiveResetSession {
    pub package: String,
    pub backups: HashMap<String, String>,
}
