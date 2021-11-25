mod account;
mod config;
mod server;
mod sm;

mod proto {
    tonic::include_proto!("kms");
}

use std::path::PathBuf;

use clap::App;
use clap::Arg;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;

use tracing::info;
use tracing::Level;

use secrecy::SecretVec;

use self::{
    account::AccountManager,
    config::{load_config, KmsConfig},
    proto::kms_server::KmsServer,
    server::KmsService,
};

#[tokio::main]
async fn main() -> Result<()> {
    // common args
    let config_arg = Arg::new("config")
        .about("the kms config")
        .takes_value(true)
        .validator(|s| s.parse::<PathBuf>())
        .default_value("config.toml");

    let stdout_arg = Arg::new("stdout")
        .about("if specified, log to stdout")
        .long("stdout")
        .conflicts_with_all(&["log-dir", "log-file-name"]);

    let log_dir_arg = Arg::new("log-dir")
        .about("the log dir")
        .short('d')
        .long("log-dir")
        .takes_value(true)
        .validator(|s| s.parse::<PathBuf>());

    let log_file_name_arg = Arg::new("log-file-name")
        .about("the log file name")
        .short('f')
        .long("log-file-name")
        .takes_value(true)
        .validator(|s| s.parse::<PathBuf>());

    // cmds
    let run_cmd = App::new("run")
        .alias("r")
        .about("run kms service")
        .arg(config_arg.clone())
        .arg(stdout_arg)
        .arg(log_dir_arg)
        .arg(log_file_name_arg);

    let mut app = App::new("kms")
        .about("KMS service for CITA-Cloud and can be used as a standalone service")
        .subcommands([run_cmd]);

    let matches = app.clone().get_matches();
    match matches.subcommand() {
        Some(("run", m)) => {
            let config = {
                let path = m.value_of("config").unwrap();
                load_config(path).context("cannot load config")?
            };

            let log_dir = m.value_of("log-dir");
            let log_file_name = m.value_of("log-file-name");
            let (writer, _guard) = if m.is_present("stdout") {
                tracing_appender::non_blocking(std::io::stdout())
            } else {
                let log_dir = log_dir.unwrap_or("logs");
                let log_file_name = log_file_name.unwrap_or("kms-service.log");
                let file_appender = tracing_appender::rolling::daily(log_dir, log_file_name);
                tracing_appender::non_blocking(file_appender)
            };

            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_ansi(false)
                .with_writer(writer)
                .init();

            set_panic_hook();

            let kms_svc = {
                let acc_mgr = account_manager(&config)
                    .await
                    .context("cannot build kms service")?;
                KmsService::new(acc_mgr)
            };

            let grpc_addr = format!("0.0.0.0:{}", config.grpc_listen_port)
                .parse()
                .unwrap();

            info!(
                "start kms service, listen grpc on `0.0.0.0:{}`",
                config.grpc_listen_port
            );
            tonic::transport::Server::builder()
                .add_service(KmsServer::new(kms_svc))
                .serve(grpc_addr)
                .await
                .context("cannot start grpc server")?;
        }
        _ => {
            app.print_help().context("cannot print help")?;
            bail!("no subcommand provided");
        }
    }

    Ok(())
}

async fn account_manager(config: &KmsConfig) -> Result<AccountManager> {
    let master_password = {
        let err_msg = "invalid master_password, must be a hex string of 26 chars";

        let pw = remove_0x(&config.master_password);
        ensure!(pw.len() == 26, err_msg);

        SecretVec::new(hex::decode(pw).context(err_msg)?)
    };

    AccountManager::new(
        &config.db_url,
        master_password,
        config.db_max_connections,
        config.db_conn_timeout_millis,
        config.db_conn_idle_timeout_millis,
    )
    .await
    .context("cannot build account manager")
}

fn set_panic_hook() {
    std::panic::set_hook(Box::new(|panic| {
        if let Some(location) = panic.location() {
            tracing::error!(
                message = %panic,
                panic.file = location.file(),
                panic.line = location.line(),
                panic.column = location.column(),
            );
        } else {
            tracing::error!(message = %panic);
        }
    }));
}

fn remove_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}
