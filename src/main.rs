mod proto;
mod config;
mod sm;
mod account;
mod server;

use std::fs;
use std::path::PathBuf;
use std::io::Read;

use clap::App;
use clap::Arg;

use url::Url;

use secrecy::SecretString;
use secrecy::ExposeSecret;

use config::load_config;
use server::CitaCloudKmsService;
use proto::KmsServiceServer;


#[tokio::main]
async fn main() {
    let run_cmd = App::new("run")
        .alias("r")
        .about("run kms service")
        .arg(
            Arg::new("config")
                .about("the kms config")
                .takes_value(true)
                .validator(|s| s.parse::<PathBuf>())
                .default_value("config.toml"),
        );

    let app = App::new("kms")
        .about("KMS service for CITA-Cloud")
        .subcommands([run_cmd]);

    let matches = app.get_matches();
    match matches.subcommand() {
        Some(("run", m)) => {
            let config = {
                let path = m.value_of("config").unwrap();
                load_config(path)
            };
            let kms_svc = {
                // TODO: Is it necessary to wrap db_password and db_url in secret?
                // I believe them will have footprint during encoding and eventually be stored somewhere non-secret, 
                // and it's less important than master_password.
                let db_url = {
                    let db_user = fs::read_to_string(&config.db_user_path).unwrap();
                    let db_password = fs::read_to_string(&config.db_password_path).unwrap();

                    let db_url: Url = fs::read_to_string(&config.db_url_path).unwrap().parse().unwrap();
                    db_url.set_username(&db_user);
                    db_url.set_password(Some(&db_password));

                    db_url.to_string()
                };
                let master_password = SecretString::new(fs::read_to_string(&config.db_password_path).unwrap());
                CitaCloudKmsService::new(&db_url, master_password).await
            };
            let grpc_addr = format!("0.0.0.0:{}", config.grpc_listen_port).parse().unwrap();
            tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(KmsServiceServer::new(kms_svc))
                    .serve(grpc_addr)
                    .await
                    .unwrap();
            });
        }
        _ => {
            println!("no command provided");
        }
    }
}
