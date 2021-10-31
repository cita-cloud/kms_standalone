use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KmsConfig {
    pub db_url_path: String,
    pub db_user_path: String,
    pub db_password_path: String,
    pub master_password_path: String,

    pub grpc_listen_port: u16,
    pub idle_timeout_millis: u64,
    pub max_connections: u64,
    pub max_cached_account: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    #[serde(rename = "kms_standalone")]
    kms: KmsConfig,
}

pub fn load_config(path: impl AsRef<Path>) -> KmsConfig {
    let s = {
        let mut f = File::open(path).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        buf
    };

    let config: Config = toml::from_str(&s).unwrap();
    config.kms
}
