mod account;
mod config;
mod proto;
mod server;
mod sm;

use std::fs;
use std::path::PathBuf;

use clap::App;
use clap::Arg;

use url::Url;

use secrecy::SecretString;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use account::AccountManager;
use config::load_config;
use proto::KmsServiceServer;
use server::CitaCloudKmsService;

#[tokio::main]
async fn main() -> Result<()> {
    let run_cmd = App::new("run").alias("r").about("run kms service").arg(
        Arg::new("config")
            .about("the kms config")
            .takes_value(true)
            .validator(|s| s.parse::<PathBuf>())
            .default_value("config.toml"),
    );

    let app = App::new("kms")
        .about("KMS service for CITA-Cloud and can be used as a standalone service")
        .subcommands([run_cmd]);

    let matches = app.get_matches();
    match matches.subcommand() {
        Some(("run", m)) => {
            let config = {
                let path = m.value_of("config").unwrap();
                load_config(path).context("cannot load config")?
            };
            let kms_svc = {
                // TODO: Is it necessary to wrap db_password and db_url in secret?
                // I believe them will have footprint during encoding and eventually be stored somewhere non-secret,
                // and it's less important than master_password.
                let db_url = {
                    let db_user =
                        fs::read_to_string(&config.db_user_path).context("cannot find db_user")?;
                    let db_password = fs::read_to_string(&config.db_password_path)
                        .context("cannot find db_password")?;
                    let mut db_url: Url = fs::read_to_string(&config.db_url_path)
                        .context("cannot find db_url")?
                        .parse()?;

                    db_url
                        .set_username(&db_user)
                        .map_err(|_| anyhow!("invalid db_url, can't set username for it"))?;
                    db_url
                        .set_password(Some(&db_password))
                        .map_err(|_| anyhow!("invalid db_url, can't set password for it"))?;

                    db_url.to_string()
                };
                let master_password =
                    SecretString::new(fs::read_to_string(&config.db_password_path)?);

                let acc_mgr = AccountManager::new(
                    &db_url,
                    master_password,
                    config.max_cached_accounts,
                    config.db_max_connections,
                    config.db_conn_timeout_millis,
                    config.db_conn_idle_timeout_millis,
                )
                .await
                .context("cannot build account manager")?;

                CitaCloudKmsService::new(acc_mgr)
            };
            let grpc_addr = format!("0.0.0.0:{}", config.grpc_listen_port)
                .parse()
                .unwrap();
            tonic::transport::Server::builder()
                .add_service(KmsServiceServer::new(kms_svc))
                .serve(grpc_addr)
                .await
                .context("cannot start grpc server")?;
        }
        _ => {
            println!("no subcommand provided");
        }
    }

    Ok(())
}
