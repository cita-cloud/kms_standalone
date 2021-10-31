use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

// Those defaults are random picked.
// Feel free to change it to some more reasonable values.
mod default {
    pub fn db_conn_idle_timeout_millis() -> u64 {
        // 15 seconds
        15 * 1000
    }

    pub fn db_max_connections() -> u32 {
        1024
    }

    pub fn max_cached_accounts() -> usize {
        1024
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KmsConfig {
    pub grpc_listen_port: u16,

    pub db_url_path: String,
    pub db_user_path: String,
    pub db_password_path: String,
    pub master_password_path: String,

    // db connection pool config
    #[serde(default = "default::db_conn_idle_timeout_millis")]
    pub db_conn_idle_timeout_millis: u64,
    #[serde(default = "default::db_max_connections")]
    pub db_max_connections: u32,

    #[serde(default = "default::max_cached_accounts")]
    pub max_cached_accounts: usize,
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
