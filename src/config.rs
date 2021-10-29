use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use serde::{Deserialize, Serialize};



#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KmsConfig {
    pub grpc_listen_port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    #[serde(rename = "kms_standalone")]
    kms: KmsConfig
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
