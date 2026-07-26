use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures::{AsyncWriteExt, StreamExt};
use libp2p::swarm::{StreamProtocol, SwarmEvent};
use libp2p::{Multiaddr, PeerId};
use link_crypto::{
    AuthorityKeyring, NonceReplayCache, VerificationContext, load_authority_keyring,
    load_or_generate_identity, verify_ticket_with_keyring,
};
use link_protocol::{
    OpenStatus, OpenTcpRequest, OpenTcpResponse, TCP_PROTOCOL, read_frame, write_frame,
};
use link_transport::{ConnectPolicy, relay_circuit_address};
use tokio::net::TcpStream;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, info, warn};

#[derive(Debug, Parser)]
#[command(
    name = "jlshell-agent",
    version,
    about = "JLShell Link remote TCP agent prototype"
)]
struct Args {
    #[arg(long, default_value = "agent-identity.key")]
    identity: PathBuf,
    #[arg(long)]
    authority_public: PathBuf,
    #[arg(long = "allow-target", required = true)]
    allowed_targets: Vec<SocketAddr>,
    #[arg(long, value_enum, default_value_t = ConnectPolicy::Auto)]
    connect_policy: ConnectPolicy,
    #[arg(long = "listen")]
    listen_addresses: Vec<Multiaddr>,
    #[arg(long)]
    relay_address: Option<Multiaddr>,
    #[arg(long)]
    relay_peer: Option<PeerId>,
}

struct Authorization {
    authority_keys: AuthorityKeyring,
    agent_peer_id: PeerId,
    allowed_targets: HashSet<SocketAddr>,
    replay_cache: NonceReplayCache,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    validate_relay_args(&args)?;

    let identity = load_or_generate_identity(&args.identity)?;
    let agent_peer_id = identity.public().to_peer_id();
    let authority_keys = load_authority_keyring(&args.authority_public)?;
    let authorization = Arc::new(Authorization {
        authority_keys,
        agent_peer_id,
        allowed_targets: args.allowed_targets.into_iter().collect(),
        replay_cache: NonceReplayCache::default(),
    });

    let mut swarm = link_transport::build_client_swarm(identity)?;
    let mut incoming = swarm
        .behaviour()
        .streams
        .new_control()
        .accept(StreamProtocol::new(TCP_PROTOCOL))
        .context("TCP stream protocol is already registered")?;

    if args.connect_policy != ConnectPolicy::RelayOnly {
        let listen_addresses = if args.listen_addresses.is_empty() {
            vec![
                "/ip4/127.0.0.1/tcp/7001".parse()?,
                "/ip4/127.0.0.1/udp/7001/quic-v1".parse()?,
            ]
        } else {
            args.listen_addresses
        };
        for address in listen_addresses {
            swarm.listen_on(address)?;
        }
    }
    if args.connect_policy != ConnectPolicy::DirectOnly {
        if let (Some(relay_address), Some(relay_peer)) = (args.relay_address, args.relay_peer) {
            swarm.listen_on(relay_circuit_address(
                &relay_address,
                relay_peer,
                Some(agent_peer_id),
            ))?;
        } else if args.connect_policy == ConnectPolicy::RelayOnly {
            bail!("relay-only requires --relay-address and --relay-peer");
        } else {
            warn!("auto policy has no relay configured; only direct connections are available");
        }
    }

    println!("AGENT_PEER_ID={agent_peer_id}");
    loop {
        tokio::select! {
            incoming_stream = incoming.next() => {
                let Some((remote_peer, stream)) = incoming_stream else {
                    bail!("incoming stream listener stopped unexpectedly");
                };
                let authorization = Arc::clone(&authorization);
                tokio::spawn(async move {
                    if let Err(error) = handle_stream(remote_peer, stream, authorization).await {
                        warn!(%remote_peer, %error, "TCP tunnel rejected or terminated");
                    }
                });
            }
            event = swarm.select_next_some() => {
                debug!(?event, "agent swarm event");
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => println!("LISTEN_ADDRESS={address}"),
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!(%peer_id, ?endpoint, "peer connected");
                    }
                    _ => {}
                }
            },
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("shutdown requested");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_stream(
    connector_peer_id: PeerId,
    mut stream: libp2p::swarm::Stream,
    authorization: Arc<Authorization>,
) -> Result<()> {
    let request: OpenTcpRequest = read_frame(&mut stream)
        .await
        .context("invalid open request")?;
    let target = parse_target(&request)?;
    if !authorization.allowed_targets.contains(&target) {
        write_rejection(
            &mut stream,
            OpenStatus::TargetDenied,
            "target is not allowed",
        )
        .await?;
        bail!("target {target} is not in the exact allow-list");
    }
    let Some(ticket) = request.ticket else {
        write_rejection(&mut stream, OpenStatus::Unauthorized, "ticket is required").await?;
        bail!("ticket is missing");
    };
    let context = VerificationContext {
        connector_peer_id,
        agent_peer_id: authorization.agent_peer_id,
        target_ip: target.ip(),
        target_port: target.port(),
        now_epoch_seconds: now_epoch_seconds()?,
    };
    if let Err(error) = verify_ticket_with_keyring(
        &ticket,
        &authorization.authority_keys,
        &context,
        &authorization.replay_cache,
    ) {
        write_rejection(&mut stream, OpenStatus::Unauthorized, &error.to_string()).await?;
        return Err(error.into());
    }

    let mut target_stream = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(error) => {
            write_rejection(
                &mut stream,
                OpenStatus::ConnectFailed,
                "target connection failed",
            )
            .await?;
            return Err(error).context("cannot connect authorized target");
        }
    };
    write_frame(
        &mut stream,
        &OpenTcpResponse {
            status: OpenStatus::Ok as i32,
            message: "connected".to_owned(),
        },
    )
    .await?;
    let mut tunnel = stream.compat();
    let copied = tokio::io::copy_bidirectional(&mut tunnel, &mut target_stream).await?;
    info!(%connector_peer_id, %target, connector_to_target = copied.0, target_to_connector = copied.1, "TCP tunnel closed");
    Ok(())
}

async fn write_rejection(
    stream: &mut libp2p::swarm::Stream,
    status: OpenStatus,
    message: &str,
) -> Result<()> {
    write_frame(
        stream,
        &OpenTcpResponse {
            status: status as i32,
            message: message.to_owned(),
        },
    )
    .await?;
    stream.close().await?;
    Ok(())
}

fn parse_target(request: &OpenTcpRequest) -> Result<SocketAddr> {
    if request.target_port == 0 || request.target_port > u32::from(u16::MAX) {
        bail!("invalid target port");
    }
    let ip = request
        .target_ip
        .parse()
        .context("target must be an exact IP address")?;
    let port = u16::try_from(request.target_port).context("invalid target port")?;
    Ok(SocketAddr::new(ip, port))
}

fn now_epoch_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system clock value is too large")
}

fn validate_relay_args(args: &Args) -> Result<()> {
    if args.relay_address.is_some() != args.relay_peer.is_some() {
        bail!("--relay-address and --relay-peer must be supplied together");
    }
    Ok(())
}
