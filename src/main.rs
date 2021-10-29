mod proto;
mod config;
mod sm;
mod account;
mod server;

use std::path::PathBuf;

use clap::App;
use clap::Arg;

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
            let grpc_addr = format!("0.0.0.0:{}", config.grpc_listen_port).parse().unwrap();
            let kms_svc = {
                let db_uri = todo!();
                let master_password = todo!();
                CitaCloudKmsService::new(db_uri, master_password).await
            };
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
