use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::App;
use clap::Arg;

use rand::{thread_rng, Rng};
use rayon::prelude::*;

use indicatif::ProgressBar;

use tonic::transport::channel::Channel;
use tonic::transport::channel::Endpoint;

use kms::proto::{kms_client::KmsClient, SignRequest};

const SM3_HASH_BYTES_LEN: usize = 32;
type Hash = [u8; SM3_HASH_BYTES_LEN];

#[tokio::main]
async fn main() {
    let app = App::new("kms-bench")
        .about("Send signing requests with {-c} workers over {--connections} connections")
        .arg(
            Arg::new("rpc-addr")
                .about("RPC address of the kms server")
                .short('r')
                .long("rpc-addr")
                .takes_value(true)
                .default_value("127.0.0.1:50055")
                .validator(str::parse::<SocketAddr>),
        )
        .arg(
            Arg::new("concurrency")
                .about(
                    "Number of request workers to run concurrently for sending signing requests. \
                    Workers will be distributed evenly among all the connections. \
                    [default: the same as total]",
                )
                .short('c')
                .long("concurrency")
                .takes_value(true)
                .required(false)
                .validator(str::parse::<u64>),
        )
        .arg(
            Arg::new("connections")
                .about("Number of connections connects to server")
                .long("connections")
                .takes_value(true)
                .default_value("16")
                .validator(str::parse::<u64>),
        )
        .arg(
            Arg::new("timeout")
                .about("Timeout for each request (in seconds). Use 0 for infinite")
                .long("timeout")
                .takes_value(true)
                .default_value("120")
                .validator(str::parse::<u64>),
        )
        .arg(
            Arg::new("batch")
                .about("Whether to use batch signing")
                .long("batch")
                .short('b'),
        )
        .arg(
            Arg::new("total")
                .about("Number of signing requests to send")
                .default_value("200")
                .validator(str::parse::<u32>),
        );

    let m = app.get_matches();

    let rpc_addr = {
        let rpc_addr = m.value_of("rpc-addr").unwrap();
        format!("http://{}", rpc_addr)
    };
    let total = m.value_of("total").unwrap().parse::<u64>().unwrap();
    let connections = m.value_of("connections").unwrap().parse::<u64>().unwrap();
    let timeout = m.value_of("timeout").unwrap().parse::<u64>().unwrap();
    let workers = m
        .value_of("concurrency")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(total);
    let use_batch = m.is_present("batch");

    let progbar = {
        let progbar = indicatif::ProgressBar::new(total);
        progbar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7}",
                )
                .progress_chars("=> "),
        );
        Arc::new(progbar)
    };

    let duration = if use_batch {
        bench_with_batch(progbar.clone(), rpc_addr, total, connections, timeout).await
    } else {
        bench_without_batch(
            progbar.clone(),
            rpc_addr,
            total,
            connections,
            workers,
            timeout,
        )
        .await
    };

    println!(
        "sending `{}` transactions finished in `{}` ms",
        total,
        duration.as_millis()
    );
    let success = progbar.position();
    let failure = total - success;
    let rps = total as f64 / (duration.as_millis() as f64 / 1000.0);
    println!(
        "`{}` success, `{}` failure, `{:.1}` req/s",
        success, failure, rps
    );
}

async fn bench_with_batch(
    progbar: Arc<ProgressBar>,
    rpc_addr: String,
    total: u64,
    connections: u64,
    timeout: u64,
) -> Duration {
    println!("Preparing connections and signing requests..");
    let conns = {
        let mut conns = vec![];
        let endpoint = {
            let mut endpoint = Endpoint::from_shared(rpc_addr.clone()).unwrap();
            if timeout > 0 {
                endpoint = endpoint.timeout(Duration::from_secs(timeout));
            }
            endpoint
        };
        for _ in 0..connections {
            let conn = endpoint.connect().await.unwrap();
            conns.push(KmsClient::new(conn));
        }
        conns
    };

    // Avoid lazy evaluation.
    #[allow(clippy::needless_collect)]
    let conn_workloads = conns
        .into_par_iter()
        .enumerate()
        .map(|(i, conn)| {
            let i = i as u64;
            // Those residual_* are for distributing residual evenly.
            let residual_reqs_for_this_conn = total % connections;

            let reqs_for_this_conn = if i < residual_reqs_for_this_conn {
                total / connections + 1
            } else {
                total / connections
            };
            let messages = (0..reqs_for_this_conn)
                .into_par_iter()
                .map(|_| {
                    let mut rng = thread_rng();
                    rng.gen::<Hash>().to_vec()
                })
                .collect();

            let req = SignRequest {
                account_id: format!("bench#{}", i),
                messages,
            };

            (conn, req)
        })
        .collect::<Vec<(KmsClient<Channel>, SignRequest)>>();

    println!("Sending transactions...");
    // Show progress bar.
    progbar.inc(0);

    let t = std::time::Instant::now();
    let hs = conn_workloads
        .into_iter()
        .map(|(mut conn, req)| {
            let progbar = progbar.clone();
            tokio::spawn(async move {
                if let Ok(res) = conn.sign(req).await {
                    let sigs = res.into_inner().signatures;
                    progbar.inc(sigs.len() as u64);
                } else {
                    progbar.inc(0);
                }
            })
        })
        .collect::<Vec<_>>();

    for h in hs {
        let _ = h.await;
    }
    progbar.finish_at_current_pos();

    t.elapsed()
}

async fn bench_without_batch(
    progbar: Arc<ProgressBar>,
    rpc_addr: String,
    total: u64,
    connections: u64,
    workers: u64,
    timeout: u64,
) -> Duration {
    println!("Preparing connections and signing requests..");
    let conns = {
        let mut conns = vec![];
        let endpoint = {
            let mut endpoint = Endpoint::from_shared(rpc_addr.to_string()).unwrap();
            if timeout > 0 {
                endpoint = endpoint.timeout(Duration::from_secs(timeout));
            }
            endpoint
        };
        for _ in 0..connections {
            let conn = endpoint.connect().await.unwrap();
            conns.push(KmsClient::new(conn));
        }
        conns
    };
    // Avoid lazy evaluation.
    #[allow(clippy::needless_collect)]
    let conn_workloads = conns
        .into_par_iter()
        .enumerate()
        .map(|(i, conn)| {
            let i = i as u64;
            // Those residual_* are for distributing residual evenly.
            let residual_reqs_for_this_conn = total % connections;
            let residual_workers_for_this_conn = workers % connections;

            let (reqs_for_this_conn, workers_for_this_conn) = {
                let reqs_for_this_conn = if i < residual_reqs_for_this_conn {
                    total / connections + 1
                } else {
                    total / connections
                };
                let workers_for_this_conn = if i < residual_workers_for_this_conn {
                    workers / connections + 1
                } else {
                    workers / connections
                };
                (reqs_for_this_conn, workers_for_this_conn)
            };

            let worker_workloads = (0..workers_for_this_conn)
                .into_par_iter()
                .map(|w| {
                    let residual_reqs_for_this_worker = reqs_for_this_conn % workers_for_this_conn;

                    let reqs_for_this_worker = if w < residual_reqs_for_this_worker {
                        reqs_for_this_conn / workers_for_this_conn + 1
                    } else {
                        reqs_for_this_conn / workers_for_this_conn
                    };

                    (0..reqs_for_this_worker)
                        .into_par_iter()
                        .map(|_| {
                            let mut rng = thread_rng();
                            let account_id = format!("bench#{}", i);
                            let msg = rng.gen::<Hash>().to_vec();

                            SignRequest {
                                account_id,
                                messages: vec![msg],
                            }
                        })
                        .collect()
                })
                .collect();

            (conn, worker_workloads)
        })
        .collect::<Vec<(KmsClient<Channel>, Vec<Vec<SignRequest>>)>>();

    println!("Sending transactions...");
    // Show progress bar.
    progbar.inc(0);

    let t = std::time::Instant::now();
    let hs = conn_workloads
        .into_iter()
        .map(|(conn, worker_workloads)| {
            let progbar = progbar.clone();
            tokio::spawn(async move {
                let hs = worker_workloads
                    .into_iter()
                    .map(|workload| {
                        let progbar = progbar.clone();
                        let mut conn = conn.clone();
                        tokio::spawn(async move {
                            for req in workload {
                                let success = conn
                                    .sign(req)
                                    .await
                                    .map(|resp| !resp.into_inner().signatures.is_empty())
                                    .unwrap_or(false);
                                progbar.inc(success as u64);
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                for h in hs {
                    let _ = h.await;
                }
            })
        })
        .collect::<Vec<_>>();

    for h in hs {
        let _ = h.await;
    }
    progbar.finish_at_current_pos();

    t.elapsed()
}
