use anyhow::{Context, Result, anyhow};
use cln_grpc::pb::node_server::NodeServer;
use cln_plugin::{Builder, Plugin, options};
use cln_rpc::notifications::Notification;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::broadcast;

mod tls;

#[derive(Clone, Debug)]
struct PluginState {
    rpc_path: PathBuf,
    identity: tls::Identity,
    ca_cert: Vec<u8>,
    events: broadcast::Sender<cln_rpc::notifications::Notification>,
}

const OPTION_GRPC_PORT: options::DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "grpc-port",
        9736,
        "Which port should the grpc plugin listen for incoming connections?",
    );

const OPTION_GRPC_HOST: options::DefaultStringConfigOption =
    options::ConfigOption::new_str_with_default(
        "grpc-host",
        "127.0.0.1",
        "Which host should the grpc listen for incomming connections?",
    );

const OPTION_GRPC_MSG_BUFFER_SIZE: options::DefaultIntegerConfigOption =
    options::ConfigOption::new_i64_with_default(
        "grpc-msg-buffer-size",
        1024,
        "Number of notifications which can be stored in the grpc message buffer. Notifications can be skipped if this buffer is full",
    );

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    unsafe {
        // SAFETY:
        // `std::env::set_var` is unsafe in Rust 2024 because environment variables
        // are process-global and unsynchronized. Concurrent reads/writes from
        // multiple threads can cause undefined behavior.
        //
        // This call happens at process startup, before any threads are spawned and
        // before any code that may read environment variables is executed.
        // Therefore, no concurrent access is possible.
        std::env::set_var(
            "CLN_PLUGIN_LOG",
            "cln_plugin=info,cln_rpc=info,cln_grpc=debug,debug",
        )
    };

    let directory = std::env::current_dir()?;

    let plugin = match Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPTION_GRPC_PORT)
        .option(OPTION_GRPC_HOST)
        .option(OPTION_GRPC_MSG_BUFFER_SIZE)
        // TODO: Use the catch-all subscribe method
        // However, doing this breaks the plugin at the time begin
        // We should fix this
        // .subscribe("*", handle_notification)
        .subscribe("balance_snapshot", handle_notification)
        .subscribe("block_added", handle_notification)
        .subscribe("channel_open_failed", handle_notification)
        .subscribe("channel_opened", handle_notification)
        .subscribe("channel_state_changed", handle_notification)
        .subscribe("coin_movement", handle_notification)
        .subscribe("connect", handle_notification)
        .subscribe("custommsg", handle_notification)
        .subscribe("disconnect", handle_notification)
        .subscribe("forward_event", handle_notification)
        .subscribe("invoice_creation", handle_notification)
        .subscribe("invoice_payment", handle_notification)
        .subscribe("onionmessage_forward_fail", handle_notification)
        .subscribe("openchannel_peer_sigs", handle_notification)
        .subscribe("pay_part_start", handle_notification)
        .subscribe("pay_part_end", handle_notification)
        .subscribe("plugin_started", handle_notification)
        .subscribe("plugin_stopped", handle_notification)
        .subscribe("sendpay_failure", handle_notification)
        .subscribe("sendpay_success", handle_notification)
        .subscribe("warning", handle_notification)
        .configure()
        .await?
    {
        Some(p) => p,
        None => return Ok(()),
    };

    let bind_port: i64 = plugin.option(&OPTION_GRPC_PORT).unwrap();
    let bind_host: String = plugin.option(&OPTION_GRPC_HOST).unwrap();
    let buffer_size: i64 = plugin.option(&OPTION_GRPC_MSG_BUFFER_SIZE).unwrap();
    let buffer_size = match usize::try_from(buffer_size) {
        Ok(b) => b,
        Err(_) => {
            plugin
                .disable("'grpc-msg-buffer-size' should be strictly positive")
                .await?;
            return Ok(());
        }
    };

    let (sender, _) = broadcast::channel(buffer_size);

    let (identity, ca_cert) = match tls::init(&directory) {
        Ok(o) => o,
        Err(e) => {
            log_error(e.to_string());
            return Err(e);
        }
    };

    let state = PluginState {
        rpc_path: PathBuf::from(plugin.configuration().rpc_file.as_str()),
        identity,
        ca_cert,
        events: sender,
    };

    let plugin = plugin.start(state.clone()).await?;

    let bind_addr: SocketAddr = format!("{}:{}", bind_host, bind_port).parse().unwrap();

    tokio::select! {
        _ = plugin.join() => {
        // This will likely never be shown, if we got here our
        // parent process is exiting and not processing out log
        // messages anymore.
            log::debug!("Plugin loop terminated")
        }
        e = run_interface(bind_addr, state) => {
            log_error(format!("Error running grpc interface: {:?}", e));
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
            cln_grpc::Server::new(&state.rpc_path, state.events.clone())
                .await
                .context("creating NodeServer instance")?,
        ))
        .serve(bind_addr);

    log::info!(
        "Connecting to {} and serving grpc on {}",
        state.rpc_path.display(),
        &bind_addr
    );

    match server.await {
        Ok(()) => (),
        Err(e) => {
            debug_who_uses_port(bind_addr.port());
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Err(anyhow!("serving requests: {e}"));
        }
    }

    Ok(())
}
fn debug_who_uses_port(port: u16) {
    log::info!("🔍 Investigating who is using port {}...", port);

    // First, get the raw socket info
    let output = std::process::Command::new("ss")
        .args(["-ltnp", &format!("sport = :{}", port)])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        if !text.trim().is_empty() {
            log::info!("Socket information:\n{}", text);
        }
    }

    // Now extract PIDs and get detailed process info
    if let Ok(out) = std::process::Command::new("ss")
        .args(["-ltnp", &format!("sport = :{}", port)])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = text.lines().collect();

        for line in lines {
            if let Some(pid_start) = line.find("pid=") {
                if let Some(pid_part) = line[pid_start..].split(',').next() {
                    let pid_str = pid_part.trim_start_matches("pid=");
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        log::info!("Found process with PID {} holding the port", pid);
                        show_process_details(pid);
                    }
                }
            }
        }
    }

    // Fallback tools
    for (name, args) in [
        ("lsof", vec!["-i", &format!(":{}", port)]),
        ("netstat", vec!["-ltnp"]),
    ] {
        if let Ok(out) = std::process::Command::new(name).args(args).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            if !s.trim().is_empty() {
                log::info!("\n{} output:\n{}", name.to_uppercase(), s);
            }
        }
    }
}

fn show_process_details(pid: u32) {
    let pid_str = pid.to_string();
    let env = format!("/proc/{}/environ", pid);
    let commands = vec![
        // Full command line
        vec!["ps", "-p", &pid_str, "-o", "pid,ppid,user,comm,args"],
        // Process tree
        vec!["pstree", "-p", "-a", &pid_str],
        // Environment (useful in CI)
        vec!["cat", &env],
    ];

    for cmd in commands {
        log::info!("\nRunning: {} {}", cmd[0], cmd[1..].join(" "));
        match std::process::Command::new(cmd[0]).args(&cmd[1..]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stdout.trim().is_empty() {
                    log::info!("{}", stdout);
                }
                if !stderr.trim().is_empty() {
                    log::warn!("{}", stderr);
                }
            }
            Err(e) => log::warn!("Failed to run {:?}: {}", cmd, e),
        }
    }
}

async fn handle_notification(plugin: Plugin<PluginState>, value: serde_json::Value) -> Result<()> {
    let notification: Result<Notification, _> = serde_json::from_value(value);
    match notification {
        Err(err) => {
            log::debug!("Failed to parse notification from lightningd {:?}", err);
        }
        Ok(notification) => {
            /* Depending on whether or not there is a wildcard
             * subscription we may receive notifications for which we
             * don't have a handler. We suppress the `SendError` which
             * would indicate there is no subscriber for the given
             * topic. */
            let _ = plugin.state().events.send(notification);
        }
    };
    Ok(())
}

fn log_error(error: String) {
    println!(
        "{}",
        serde_json::json!({"jsonrpc": "2.0",
                          "method": "log",
                          "params": {"level":"warn", "message":error}})
    );
}
