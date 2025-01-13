//! # Forward proxy
//!
//! Simple Forward proxy implementation for testing pluggable transports
//! and meeting basic censorship circumvention proxy needs.
//!
//! ` [client] <---> [fwd\_client] <====> [fwd\_server] <---> [target] `
//!
//! ⚠️  🚧 WARNING This crate is still under construction 🚧 ⚠️
//! - interface subject to change at any time
//! - Not production ready
//!   - do not rely on this for any security critical applications
//!
//!
//! Usage info:
//!
//! ```txt
//! Generalized forward proxy client and server for transparently proxying traffic over PTs.
//!
//! Usage: fwd [OPTIONS] [LADDR] <COMMAND>
//!
//! Commands:
//!   client  Run as client forward proxy, initiating pluggable transport connection
//!   server  Run as server, terminating the pluggable transport protocol
//!   help    Print this message or the help of the given subcommand(s)
//!
//! Arguments:
//!   [LADDR]  Listen address, defaults to "[::]:9000" for client, "[::]:9001" for server
//!
//! Options:
//!   -a, --args <ARGS>            Transport argument string
//!   -s, --state-dir <DIR>        Path to a directory where launch state is located.
//!   -l, --log-level <LOG_LEVEL>  Log Level (ERROR/WARN/INFO/DEBUG/TRACE) [default: INFO]
//!   -x, --unsafe-logging         Disable the address scrubber on logging
//!   -h, --help                   Print help
//!   -V, --version                Print version
//! ```
//!
//! Examples
//!
//!
//! ```sh
//! fwd -s ./state/ server fwd "127.0.0.1:5201"
//! ```
//!
//! ```sh
//! fwd -a "cert=AAAAAAAAAAAAAAAAAAAAAAAAAADTSFvsGKxNFPBcGdOCBSgpEtJInG9zCYZezBPVBuBWag;iat-mode=0" -l DEBUG 127.0.0.1:9000 client 127.0.0.1:9001
//! ```
//!
//! ### Installation
//!
//! The `fwd` binary is co-located within the `lyrebird` crate, to install:
//!
//! ```sh
//! # install all binaries within the lyrebird crate (`lyrebird`, and `fwd`)
//! cargo install lyrebird
//!
//! # install only the `fwd` binary
//! cargo install lyrebird --bin fwd
//! ```
//!
//! This installs in the configured Rust location (i.e. `$HOME/.cargo/bin`). You may
//! wish to copy `./fwd` to a permanent location (e.g. `/usr/local/bin`).
//!
//! ### Tips and tricks
//!
//!  * On modern Linux systems it is possible to have fwd bind to reserved
//!    ports (<=1024) even when not running as root by granting the
//!    `CAP_NET_BIND_SERVICE` capability with setcap:
//!
//!    `# setcap 'cap_net_bind_service=+ep' /usr/local/bin/fwd`
//!
//!
//! ## Potential Features
//!
//! - [ ] geoip for obvious signs of censorship
//! - [ ] tracking resets / injections / replays
//! - [ ] tunnel metrics - throughput / bytes-per-tunnel / etc.
//! - [ ] socks proxy handler in fwd
//!
//! ---
//!
//! TODO: (priority: after mvp)
//!   - use tunnel_manager for managing proxy connections so we can track metrics
//!     about tunnel failures and bytes transferred.
//!   - find a way to apply a rate limit to copy bidirectional
//!   - use the better copy interactive for bidirectional copy
#![allow(unused)]

use futures::Future;
use obfs4::Obfs4PT;
use ptrs::{args::Args, PluggableTransport, ServerBuilder, ServerTransport};
use ptrs::{debug, error, info, warn};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
// use fast_socks5::{
//     server::{DenyAuthentication, SimpleUserPassword},
//     util::target_addr::TargetAddr,
//     AuthenticationMethod,
// };
use safelog::sensitive;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal::unix::SignalKind,
    sync::oneshot,
};
use tokio::{net::ToSocketAddrs, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{filter::LevelFilter, prelude::*};

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

mod backend;
use backend::{Backend, Backends};

/// Client Socks address to listen on.
const U4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);
const U6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 9000);

const DEV_ARG: &str = "dev";

#[derive(Parser)]
#[command(author, version, long_about = None, about="Generalized client and server for transparently proxying traffic over PTs.")]
struct CliArgs {
    /// Run in server mode or client mode
    #[command(subcommand)]
    mode: Mode,

    /// Listen address, defaults to "[::]:9000" for client, "[::]:9001" for server
    laddr: Option<String>,

    /// Transport argument string
    #[arg(short, long)]
    args: Option<String>,

    /// Log Level (ERROR/WARN/INFO/DEBUG/TRACE)
    #[arg(short, long, default_value_t=String::from("INFO"))]
    log_level: String,

    /// Disable the address scrubber on logging
    #[arg(short = 'x', long, action)]
    unsafe_logging: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Subcommand)]
enum Mode {
    /// Run as client forward proxy, initiating pluggable transport connection.
    Client {
        /// Target address, server address when running as client, forward address when running as
        dst: String,
    },

    /// Run as server, terminating the pluggable transport protocol
    #[command(subcommand)]
    Server(
        /// Backend hadler by name, with args.
        Backends,
    ),
}

/// Initialize the logging receiver(s) for things to be logged into using the
/// tracing / tracing_subscriber libraries
fn init_logging_recvr(unsafe_logging: bool, level_str: &str) -> Result<safelog::Guard> {
    let log_lvl = LevelFilter::from_str(level_str)?;

    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(log_lvl);

    tracing_subscriber::registry()
        .with(console_layer.boxed())
        .init();
    warn!("log level set to {level_str}");

    if unsafe_logging {
        info!("⚠️ ⚠️  unsafe logging enabled ⚠️ ⚠️ ");
        safelog::disable_safe_logging().context("failed to get safelog Guard")
    } else {
        safelog::enforce_safe_logging().context("failed to get safelog Guard")
    }
}

fn ingest_args(cli_args: &CliArgs) -> Option<Args> {
    match &cli_args.args {
        None => None,
        #[cfg(debug_assertions)]
        Some(a) if a == DEV_ARG => match &cli_args.mode {
            Mode::Client { dst: _ } => Args::from_str(obfs4::dev::CLIENT_ARGS).ok(),
            Mode::Server(_backend) => Args::from_str(obfs4::dev::SERVER_ARGS).ok(),
        },
        Some(a) => Args::from_str(a).ok(),
    }
}

/// Main function, ties everything together and parses arguments etc.
#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();

    // launch tracing subscriber with filter level
    let _guard = init_logging_recvr(args.unsafe_logging, &args.log_level)?;

    let listen_addr = match &args.laddr {
        Some(a) => a,
        None => match &args.mode {
            Mode::Client { dst: _ } => "[::]:9000",
            Mode::Server(_backend) => "[::]:9001",
        },
    };

    let params = ingest_args(&args);

    // launch runners
    let cancel_token = tokio_util::sync::CancellationToken::new();

    let mut exit_rx = match args.mode {
        Mode::Client { dst } => {
            // running as CLIENT
            let params =
                params.ok_or(anyhow!("missing arguments for client to connect to server"))?;

            let dst_addr = dst.parse()?;

            client_setup(listen_addr, dst_addr, params, cancel_token.clone()).await?
        }
        Mode::Server(backend) => {
            // running as SERVER
            server_setup(listen_addr, backend.arc(), params, cancel_token.clone()).await?
        }
    };

    info!("accepting connections");

    // At this point, the pt config protocol is finished, and incoming
    // connections will be processed.  Wait till the parent dies
    // (immediate exit), a SIGTERM is received (immediate exit),
    // or a SIGINT is received.
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        _ = &mut exit_rx => {
            info!("proxy closed");
            return Ok(())
        }
        _ = sigterm.recv() => {
            info!("proxy terminated");
            return Ok(())
        }
        _ = sigint.recv()=> {
            info!("received iterrupt, shutting down");
            cancel_token.cancel();
        }
    }

    // Ok, it was the first SIGINT, close all listeners, and wait till,
    // the parent dies, all the current connections are closed, or either
    // a SIGINT/SIGTERM is received, and exit.
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        _ = exit_rx => {}
        _ = sigint.recv()=> {}
        _ = sigterm.recv() => {}
    }

    Ok(())
}

async fn warn_fut(client_addr: SocketAddr, f: impl Future<Output = Result<()>>) {
    if let Err(e) = f.await {
        warn!(address = sensitive(client_addr).to_string(), "{e}");
    }
}

// ================================================================ //
//                            Client                                //
// ================================================================ //

async fn client_setup<A: ToSocketAddrs>(
    listen_addrs: A,
    remote_addr: SocketAddr,
    params: Args,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let obfs4_name = Obfs4PT::name();
    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    debug!("({obfs4_name}) client building with {:?}", params);
    let builder = Obfs4PT::client_builder();
    let listener = tokio::net::TcpListener::bind(listen_addrs).await?;

    listeners.push(warn_fut(
        listener.local_addr()?,
        client_accept_loop(listener, builder, remote_addr, params, cancel_token.clone()),
    ));

    // spawn a task that runs and monitors the progress of the listeners.
    tokio::spawn(async move {
        let total_len = listeners.len();
        let mut running = total_len;

        // launch all listener futures
        let mut pt_set = JoinSet::new();
        for fut in listeners {
            pt_set.spawn(fut);
        }

        // if any of the listeners exit, handle it
        while let Some(res) = pt_set.join_next().await {
            running -= 1;
            if let Err(e) = res {
                warn!("listener failed: {e}");
            }
            info!("({obfs4_name}) {running}/{total_len} listeners running");
        }

        // if all listeners exit then we can send the tx signal.
        tx.send(true).unwrap()
    });

    Ok(rx)
}

async fn client_accept_loop<C>(
    listener: TcpListener,
    mut builder: impl ptrs::ClientBuilder<TcpStream, ClientPT = C> + Send + 'static,
    remote_addr: SocketAddr,
    params: Args,
    cancel_token: CancellationToken,
) -> Result<()>
where
    // the provided client builder should build the C ClientTransport.
    C: ptrs::ClientTransport<TcpStream, std::io::Error> + Send + 'static,
{
    let pt_name = C::method_name();
    let builder = builder.options(&params)?;

    info!(
        "{pt_name} client accept loop launched listening on: {}",
        listener.local_addr()?
    );
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("{pt_name} received shutdown signal");
                break
            }
            res = listener.accept() => {
                let (conn, client_addr) = match res {
                    Err(e) => {
                        error!("failed to accept tcp connection {e}");
                        break;
                    }
                    Ok(c) => c,
                };
                debug!("accepted new connection -> {}:{}", sensitive(client_addr.ip()), client_addr.port());
                tokio::spawn(warn_fut(client_addr, client_handle_connection(conn, builder.clone(), remote_addr, client_addr)));
            }
        }
    }

    Ok(())
}

/// This function assumes that the provided connection / socket manages reconstruction
/// and reliability before passing to this layer.
async fn client_handle_connection<In, C>(
    mut conn: In,
    builder: impl ptrs::ClientBuilder<TcpStream, ClientPT = C> + 'static,
    remote_addr: SocketAddr,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided T must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Unpin,
    // the provided client builder should build the C ClientTransport.
    C: ptrs::ClientTransport<TcpStream, std::io::Error>,
{
    let remote = tokio::net::TcpStream::connect(remote_addr);

    let pt_client = builder.build();

    // build the pluggable transport client and then dial, completing the
    // connection and handshake when the `wrap(..)` is await-ed.
    let mut pt_conn = match ptrs::ClientTransport::<TcpStream, std::io::Error>::establish(
        pt_client,
        Box::pin(remote),
    )
    .await
    {
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "handshake failed: {e}"
            );
            conn.shutdown().await?;
            return Err(obfs4::Error::from(e.to_string())).context("handshake failed");
        }
        Ok(c) => c,
    };

    match copy_bidirectional(&mut conn, &mut pt_conn).await {
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed with error: {e}"
            );
        }
        Ok((up, down)) => {
            info!(
                address = sensitive(client_addr).to_string(),
                "tunnel closed {up} {down}"
            );
        }
    }
    Ok(())
}

// ================================================================ //
//                            Server                                //
// ================================================================ //

async fn server_setup<A: ToSocketAddrs, B>(
    listen_addrs: A,
    backend: B,
    params: Option<Args>,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>>
where
    B: Backend + Clone + Send + Sync + 'static,
{
    let obfs4_name = Obfs4PT::name();

    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    let mut builder = Obfs4PT::server_builder();
    if params.is_some() {
        builder.options(&params.unwrap())?;
    }

    let client_options = builder.get_client_params();
    let server = builder.build();

    info!("({obfs4_name}) client params: \"{}\"", client_options);

    let listener = tokio::net::TcpListener::bind(listen_addrs).await?;
    listeners.push(server_listen_loop::<TcpStream, _, _>(
        listener,
        server,
        backend.clone(),
        cancel_token.clone(),
    ));

    // spawn a task that runs and monitors the progress of the listeners.
    tokio::spawn(async move {
        let total_len = listeners.len();
        let mut running = total_len;

        // launch all listener futures
        let mut pt_set = JoinSet::new();
        for fut in listeners {
            pt_set.spawn(fut);
        }

        // if any of the listeners exit, handle it
        while let Some(res) = pt_set.join_next().await {
            running -= 1;
            if let Err(e) = res {
                warn!("listener failed: {e}");
            }
            info!("({obfs4_name}) {running}/{total_len} listeners running");
        }

        // if all listeners exit then we can send the tx signal.
        tx.send(true).unwrap()
    });

    Ok(rx)
}

async fn server_listen_loop<In, S, B>(
    listener: TcpListener,
    server: S,
    backend: B,
    cancel_token: CancellationToken,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
    S: ptrs::ServerTransport<In> + Clone + Send + Sync + 'static,
    S: ptrs::ServerTransport<TcpStream>,
    // S: ptrs::ServerTransport<TcpStream> + Clone,
    <S as ptrs::ServerTransport<In>>::OutErr: 'static,
    <S as ptrs::ServerTransport<TcpStream>>::OutRW: Sync,
    B: Backend + Clone + Send + Sync + 'static,
{
    let method_name = <S as ServerTransport<In>>::method_name();
    info!(
        "{method_name} server accept loop launched listening on: {}",
        listener.local_addr()?
    );
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("{method_name} received shutdown signal - closing listener");
                break
            }
            res = listener.accept() => {
                let (conn, client_addr) = match res {
                    Err(e) => {
                       error!("{method_name} closing listener - failed to accept tcp connection {e}");
                       break;
                   }
                   Ok(c) => c,
               };
               debug!("accepted new connection -> {}:{}", sensitive(client_addr.ip()), client_addr.port());
               tokio::spawn(warn_fut(client_addr, server_handle_connection(
                   conn,
                   server.clone(),
                   backend.clone(),
                   client_addr,
               )));
            }
        }
    }

    Ok(())
}

async fn server_handle_connection<In, S, B>(
    conn: In,
    server: S,
    backend: B,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
    S: ptrs::ServerTransport<In> + Clone + Send + Sync + 'static,
    S: ptrs::ServerTransport<TcpStream>,
    <S as ptrs::ServerTransport<In>>::OutErr: Send + Sync + 'static,
    <S as ptrs::ServerTransport<In>>::OutRW: Send + Sync + 'static,
    B: Backend + Clone + Send + Sync,
{
    let pt_conn = server
        .reveal(conn)
        .await
        .context("server handshake failed")?;

    backend.handle(pt_conn, client_addr).await?;

    Ok(())
}
