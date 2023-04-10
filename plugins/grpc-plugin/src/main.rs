use anyhow::{anyhow, Context, Result};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::{options, Builder};
use log::{debug, info, warn};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod config;
mod hooks;
mod tls;
mod util;

#[derive(Clone, Debug)]
pub struct PluginState {
    pub config: Arc<Mutex<config::Config>>,
    pub blockheight: Arc<Mutex<u64>>,
    pub invoice_amts: Arc<Mutex<HashMap<String, u64>>>,
    rpc_path: PathBuf,
    identity: tls::Identity,
    ca_cert: Vec<u8>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    debug!("Starting grpc plugin");
    std::env::set_var("CLN_PLUGIN_LOG", "debug");
    let path = Path::new("lightning-rpc");

    let directory = std::env::current_dir()?;
    let (identity, ca_cert) = tls::init(&directory)?;

    let state = PluginState {
        config: Arc::new(Mutex::new(config::Config::new())),
        blockheight: Arc::new(Mutex::new(u64::default())),
        invoice_amts: Arc::new(Mutex::new(HashMap::new())),
        rpc_path: path.into(),
        identity,
        ca_cert,
    };

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(options::ConfigOption::new(
            "grpc-port",
            options::Value::Integer(50973),
            "Which port should the grpc plugin listen for incoming connections?",
        ))
        .hook("htlc_accepted", hooks::htlc_handler)
        .subscribe("block_added", hooks::block_added)
        .dynamic()
        .configure()
        .await?
    {
        Some(p) => {
            info!("read config");
            match config::read_config(&p, state.clone()).await {
                Ok(()) => &(),
                Err(e) => return p.disable(format!("{}", e).as_str()).await,
            };
            p
        }
        None => return Ok(()),
    };

    let bind_port = match plugin.option("grpc-port") {
        Some(options::Value::Integer(-1)) => {
            log::info!("`grpc-port` option is not configured, exiting.");
            plugin
                .disable("`grpc-port` option is not configured.")
                .await?;
            return Ok(());
        }
        Some(options::Value::Integer(i)) => i,
        None => return Err(anyhow!("Missing 'grpc-port' option")),
        Some(o) => return Err(anyhow!("grpc-port is not a valid integer: {:?}", o)),
    };

    let plugin = plugin.start(state.clone()).await?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", bind_port).parse().unwrap();

    tokio::select! {
        _ = plugin.join() => {
        // This will likely never be shown, if we got here our
        // parent process is exiting and not processing out log
        // messages anymore.
            debug!("Plugin loop terminated")
        }
        e = run_interface(bind_addr, state) => {
            warn!("Error running grpc interface: {:?}", e)
        }
    }
    Ok(())
}

async fn run_interface(bind_addr: SocketAddr, state: PluginState) -> Result<()> {
    let identity = state.identity.to_tonic_identity();
    let ca_cert = tonic::transport::Certificate::from_pem(state.ca_cert);

    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    let server = tonic::transport::Server::builder()
        .tls_config(tls)
        .context("configuring tls")?
        .add_service(NodeServer::new(
            cln_grpc::Server::new(&state.rpc_path)
                .await
                .context("creating NodeServer instance")?,
        ))
        .serve(bind_addr);

    debug!(
        "Connecting to {:?} and serving grpc on {:?}",
        &state.rpc_path, &bind_addr
    );

    server.await.context("serving requests")?;

    Ok(())
}
