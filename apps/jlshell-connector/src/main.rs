use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{StreamProtocol, SwarmEvent};
use libp2p::{Multiaddr, PeerId};
use link_crypto::load_or_generate_identity;
use link_protocol::{
    OpenStatus, OpenTcpRequest, OpenTcpResponse, SignedTicket, TCP_PROTOCOL, read_frame,
    write_frame,
};
use link_transport::{
    ConnectPolicy, DIRECT_DIAL_TIMEOUT_SECONDS, QUIC_DIAL_PRIORITY_SECONDS, ensure_expected_peer,
    is_quic_address, is_relay_address, relay_circuit_address,
};
use prost::Message;
use tokio::net::TcpListener;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(
    name = "jlshell-connector",
    version,
    about = "JLShell Link local TCP connector prototype"
)]
struct Args {
    #[arg(long, default_value = "connector-identity.key")]
    identity: PathBuf,
    #[arg(long)]
    agent_peer: PeerId,
    #[arg(long = "agent-address")]
    agent_addresses: Vec<Multiaddr>,
    #[arg(long)]
    relay_address: Option<Multiaddr>,
    #[arg(long)]
    relay_peer: Option<PeerId>,
    #[arg(long, value_enum, default_value_t = ConnectPolicy::Auto)]
    connect_policy: ConnectPolicy,
    #[arg(long)]
    ticket: PathBuf,
    #[arg(long)]
    target: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:0")]
    local_bind: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionPath {
    Direct,
    Relay,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    validate_args(&args)?;
    let ticket = SignedTicket::decode(fs::read(&args.ticket)?.as_slice())
        .context("ticket file is not a valid signed-ticket envelope")?;
    let identity = load_or_generate_identity(&args.identity)?;
    let connector_peer_id = identity.public().to_peer_id();
    let mut swarm = link_transport::build_client_swarm(identity)?;

    let path = establish_connection(&mut swarm, &args).await?;
    println!("CONNECTOR_PEER_ID={connector_peer_id}");
    println!("CONNECTION_PATH={path:?}");

    let mut control = swarm.behaviour().streams.new_control();
    let swarm_task = tokio::spawn(async move {
        while let Some(event) = swarm.next().await {
            if let SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } = event
            {
                info!(%peer_id, ?endpoint, "additional connection established");
            }
        }
    });

    let listener = TcpListener::bind(args.local_bind).await?;
    println!("LISTEN_ADDRESS={}", listener.local_addr()?);
    let (mut local_stream, local_peer) = listener.accept().await?;
    info!(%local_peer, "local client connected");

    let mut tunnel = control
        .open_stream(args.agent_peer, StreamProtocol::new(TCP_PROTOCOL))
        .await
        .context("agent did not accept the JLShell TCP protocol")?;
    write_frame(
        &mut tunnel,
        &OpenTcpRequest {
            ticket: Some(ticket),
            target_ip: args.target.ip().to_string(),
            target_port: u32::from(args.target.port()),
        },
    )
    .await?;
    let response: OpenTcpResponse = read_frame(&mut tunnel).await?;
    if OpenStatus::try_from(response.status).unwrap_or(OpenStatus::Unspecified) != OpenStatus::Ok {
        bail!("agent rejected tunnel: {}", response.message);
    }

    let mut tunnel = tunnel.compat();
    let copied = tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel).await?;
    info!(
        local_to_agent = copied.0,
        agent_to_local = copied.1,
        "TCP tunnel closed"
    );
    swarm_task.abort();
    let _ = swarm_task.await;
    Ok(())
}

async fn establish_connection(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    args: &Args,
) -> Result<ConnectionPath> {
    if args.connect_policy != ConnectPolicy::RelayOnly && !args.agent_addresses.is_empty() {
        let (quic_addresses, fallback_addresses): (Vec<_>, Vec<_>) = args
            .agent_addresses
            .iter()
            .cloned()
            .partition(is_quic_address);
        let remaining_timeout_seconds = if quic_addresses.is_empty() {
            start_direct_dials(swarm, fallback_addresses, args.agent_peer);
            DIRECT_DIAL_TIMEOUT_SECONDS
        } else {
            start_direct_dials(swarm, quic_addresses, args.agent_peer);
            if let Ok(result) = tokio::time::timeout(
                Duration::from_secs(QUIC_DIAL_PRIORITY_SECONDS),
                wait_for_agent(swarm, args.agent_peer),
            )
            .await
            {
                return result;
            }
            warn!("QUIC priority window elapsed; trying TCP + Noise/Yamux fallback");
            start_direct_dials(swarm, fallback_addresses, args.agent_peer);
            DIRECT_DIAL_TIMEOUT_SECONDS - QUIC_DIAL_PRIORITY_SECONDS
        };
        match tokio::time::timeout(
            Duration::from_secs(remaining_timeout_seconds),
            wait_for_agent(swarm, args.agent_peer),
        )
        .await
        {
            Ok(result) => return result,
            Err(_) if args.connect_policy == ConnectPolicy::DirectOnly => {
                bail!("direct connection timed out after {DIRECT_DIAL_TIMEOUT_SECONDS} seconds")
            }
            Err(_) => warn!("direct connection timed out; falling back to relay"),
        }
    } else if args.connect_policy == ConnectPolicy::DirectOnly {
        bail!("direct-only requires at least one --agent-address");
    }

    let relay_address = args
        .relay_address
        .as_ref()
        .context("relay fallback requires --relay-address")?;
    let relay_peer = args
        .relay_peer
        .context("relay fallback requires --relay-peer")?;
    let address = relay_circuit_address(relay_address, relay_peer, Some(args.agent_peer));
    swarm
        .dial(address.clone())
        .with_context(|| format!("cannot dial relay circuit {address}"))?;
    wait_for_agent(swarm, args.agent_peer).await
}

fn start_direct_dials(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    addresses: Vec<Multiaddr>,
    expected_peer: PeerId,
) {
    for mut address in addresses {
        ensure_expected_peer(&mut address, expected_peer);
        if let Err(error) = swarm.dial(address.clone()) {
            warn!(%address, %error, "direct dial could not be started");
        }
    }
}

async fn wait_for_agent(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    expected_peer: PeerId,
) -> Result<ConnectionPath> {
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } if peer_id == expected_peer => {
                let address = match endpoint {
                    ConnectedPoint::Dialer { address, .. } => address,
                    ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
                };
                return Ok(if is_relay_address(&address) {
                    ConnectionPath::Relay
                } else {
                    ConnectionPath::Direct
                });
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } if peer_id == expected_peer => {
                warn!(%peer_id, %error, "connection attempt failed");
            }
            _ => {}
        }
    }
}

fn validate_args(args: &Args) -> Result<()> {
    if !args.local_bind.ip().is_loopback() {
        bail!("--local-bind must use 127.0.0.1 or ::1");
    }
    if args.relay_address.is_some() != args.relay_peer.is_some() {
        bail!("--relay-address and --relay-peer must be supplied together");
    }
    if args.target.ip() == IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        || args.target.ip() == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    {
        bail!("--target must be an exact, non-unspecified IP address");
    }
    Ok(())
}
