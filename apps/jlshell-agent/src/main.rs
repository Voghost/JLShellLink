use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use futures::{AsyncWriteExt, StreamExt};
use libp2p::swarm::{StreamProtocol, SwarmEvent};
use libp2p::{Multiaddr, PeerId};
use link_control_plane::{ControlPlaneClient, read_node_credential};
use link_crypto::{
    AuthorityKeyring, NonceReplayCache, VerificationContext, load_authority_keyring,
    load_or_generate_identity, parse_authority_keyring, sign_identity_payload,
    verify_ticket_with_keyring,
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
    /// Create/load the Agent identity, print its PeerId/public key, then exit.
    #[arg(long)]
    print_identity: bool,
    /// Sign one base64url control-plane challenge payload, then exit.
    #[arg(long, conflicts_with = "print_identity")]
    identity_proof: Option<String>,
    #[arg(long)]
    authority_public: Option<PathBuf>,
    #[arg(long = "allow-target")]
    allowed_targets: Vec<SocketAddr>,
    #[arg(long, value_enum, default_value_t = ConnectPolicy::Auto)]
    connect_policy: ConnectPolicy,
    #[arg(long = "listen")]
    listen_addresses: Vec<Multiaddr>,
    #[arg(long)]
    relay_address: Option<Multiaddr>,
    #[arg(long)]
    relay_peer: Option<PeerId>,
    /// HTTPS website base URL used for heartbeats and Authority refresh.
    #[arg(long)]
    control_plane_url: Option<String>,
    /// File containing the short-lived Agent credential (0600 on Unix).
    #[arg(long, requires = "control_plane_url")]
    credential_file: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(10..=3600))]
    heartbeat_seconds: u64,
}

struct Authorization {
    authority_keys: tokio::sync::RwLock<AuthorityKeyring>,
    agent_peer_id: PeerId,
    allowed_targets: HashSet<SocketAddr>,
    replay_cache: NonceReplayCache,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    if args.print_identity || args.identity_proof.is_some() {
        print_identity(&args)?;
        return Ok(());
    }
    validate_relay_args(&args)?;

    let identity = load_or_generate_identity(&args.identity)?;
    let agent_peer_id = identity.public().to_peer_id();
    let authority_path = args
        .authority_public
        .as_ref()
        .context("--authority-public is required in Agent mode")?;
    if args.allowed_targets.is_empty() {
        bail!("at least one --allow-target is required in Agent mode");
    }
    let authority_keys = load_authority_keyring(authority_path)?;
    let authorization = Arc::new(Authorization {
        authority_keys: tokio::sync::RwLock::new(authority_keys),
        agent_peer_id,
        allowed_targets: args.allowed_targets.iter().copied().collect(),
        replay_cache: NonceReplayCache::default(),
    });
    start_control_plane(&args, Arc::clone(&authorization))?;

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
    let authority_keys = authorization.authority_keys.read().await;
    if let Err(error) = verify_ticket_with_keyring(
        &ticket,
        &authority_keys,
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

fn print_identity(args: &Args) -> Result<()> {
    let identity = load_or_generate_identity(&args.identity)?;
    let public_key = identity
        .public()
        .try_into_ed25519()
        .context("Agent identity is not Ed25519")?;
    println!("AGENT_PEER_ID={}", identity.public().to_peer_id());
    println!(
        "AGENT_PUBLIC_KEY={}",
        URL_SAFE_NO_PAD.encode(public_key.to_bytes())
    );
    if let Some(payload) = &args.identity_proof {
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .context("--identity-proof must be base64url encoded")?;
        println!(
            "AGENT_PROOF_SIGNATURE={}",
            URL_SAFE_NO_PAD.encode(sign_identity_payload(&identity, &payload)?)
        );
    }
    println!("AGENT_EVENT=IDENTITY_READY");
    Ok(())
}

fn start_control_plane(args: &Args, authorization: Arc<Authorization>) -> Result<()> {
    let Some(base_url) = &args.control_plane_url else {
        if args.credential_file.is_some() {
            bail!("--credential-file requires --control-plane-url");
        }
        return Ok(());
    };
    let credential_path = args
        .credential_file
        .as_ref()
        .context("--credential-file is required with --control-plane-url")?;
    let credential = read_node_credential(credential_path)?;
    let client = ControlPlaneClient::new(base_url)?;
    let seconds = args.heartbeat_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(seconds));
        loop {
            interval.tick().await;
            if let Err(error) = client
                .agent_heartbeat(&credential, env!("CARGO_PKG_VERSION"))
                .await
            {
                warn!(%error, "Agent control-plane heartbeat failed");
            }
            match client
                .authority_keyring()
                .await
                .and_then(|bytes| parse_authority_keyring(&bytes).map_err(anyhow::Error::from))
            {
                Ok(keys) => *authorization.authority_keys.write().await = keys,
                Err(error) => {
                    warn!(%error, "ticket Authority refresh failed; keeping last valid keyring");
                }
            }
        }
    });
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
