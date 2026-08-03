use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{StreamProtocol, SwarmEvent};
use libp2p::{Multiaddr, PeerId};
use link_crypto::{load_or_generate_identity, sign_identity_payload};
use link_protocol::{
    OpenStatus, OpenTcpRequest, OpenTcpResponse, RELAY_AUTH_PROTOCOL, RelayAuthRequest,
    RelayAuthResponse, RelayAuthStatus, SignedTicket, TCP_PROTOCOL, read_frame, write_frame,
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
    /// Create/load the connector identity, print its `PeerId`, then exit.
    #[arg(long)]
    print_identity: bool,
    /// Sign one base64url control-plane challenge payload, then exit.
    #[arg(long, conflicts_with = "print_identity")]
    identity_proof: Option<String>,
    #[arg(long)]
    agent_peer: Option<PeerId>,
    #[arg(long = "agent-address")]
    agent_addresses: Vec<Multiaddr>,
    #[arg(long)]
    relay_address: Option<Multiaddr>,
    #[arg(long)]
    relay_peer: Option<PeerId>,
    /// File containing the short-lived Relay Grant. Never pass the credential directly on CLI.
    #[arg(long)]
    relay_grant: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ConnectPolicy::Auto)]
    connect_policy: ConnectPolicy,
    #[arg(long)]
    ticket: Option<PathBuf>,
    #[arg(long)]
    target: Option<SocketAddr>,
    #[arg(long, default_value = "127.0.0.1:0")]
    local_bind: SocketAddr,
}

#[derive(Debug)]
struct RunArgs {
    agent_peer: PeerId,
    agent_addresses: Vec<Multiaddr>,
    relay_address: Option<Multiaddr>,
    relay_peer: Option<PeerId>,
    relay_grant: Option<PathBuf>,
    connect_policy: ConnectPolicy,
    ticket: PathBuf,
    target: SocketAddr,
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
    if args.print_identity || args.identity_proof.is_some() {
        let identity = load_or_generate_identity(&args.identity)?;
        let connector_peer_id = identity.public().to_peer_id();
        let public_key = identity
            .public()
            .try_into_ed25519()
            .context("Connector identity is not Ed25519")?;
        println!("CONNECTOR_PEER_ID={connector_peer_id}");
        println!(
            "CONNECTOR_PUBLIC_KEY={}",
            URL_SAFE_NO_PAD.encode(public_key.to_bytes())
        );
        if let Some(payload) = args.identity_proof {
            let payload = URL_SAFE_NO_PAD
                .decode(payload)
                .context("--identity-proof must be base64url encoded")?;
            let signature = sign_identity_payload(&identity, &payload)?;
            println!(
                "CONNECTOR_PROOF_SIGNATURE={}",
                URL_SAFE_NO_PAD.encode(signature)
            );
        }
        println!("CONNECTOR_EVENT=IDENTITY_READY");
        return Ok(());
    }
    let identity_path = args.identity.clone();
    let args = RunArgs::try_from(args)?;
    validate_args(&args)?;
    let identity = load_or_generate_identity(&identity_path)?;
    let connector_peer_id = identity.public().to_peer_id();
    let ticket = SignedTicket::decode(fs::read(&args.ticket)?.as_slice())
        .context("ticket file is not a valid signed-ticket envelope")?;
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
    println!("CONNECTOR_EVENT=TUNNEL_LISTENING");
    let (mut local_stream, local_peer) = listener.accept().await?;
    println!("CONNECTOR_EVENT=LOCAL_CONNECTED");
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
    println!("CONNECTOR_EVENT=TUNNEL_CLOSED");
    swarm_task.abort();
    let _ = swarm_task.await;
    Ok(())
}

async fn establish_connection(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    args: &RunArgs,
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
    let mut relay_direct_address = relay_address.clone();
    ensure_expected_peer(&mut relay_direct_address, relay_peer);
    swarm
        .dial(relay_direct_address.clone())
        .with_context(|| format!("cannot dial relay {relay_direct_address}"))?;
    wait_for_peer(swarm, relay_peer).await?;

    if let Some(grant_file) = &args.relay_grant {
        authenticate_relay(swarm, relay_peer, args.agent_peer, grant_file).await?;
    } else {
        warn!(
            "no Relay Grant supplied; only an explicitly unauthenticated loopback Relay can accept this circuit"
        );
    }
    let address = relay_circuit_address(relay_address, relay_peer, Some(args.agent_peer));
    swarm
        .dial(address.clone())
        .with_context(|| format!("cannot dial relay circuit {address}"))?;
    wait_for_agent(swarm, args.agent_peer).await
}

async fn wait_for_peer(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    expected_peer: PeerId,
) -> Result<()> {
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == expected_peer => {
                return Ok(());
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } if peer_id == expected_peer => bail!("cannot connect to Relay {peer_id}: {error}"),
            _ => {}
        }
    }
}

async fn authenticate_relay(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    relay_peer: PeerId,
    agent_peer: PeerId,
    grant_file: &PathBuf,
) -> Result<()> {
    let grant_credential = fs::read_to_string(grant_file)
        .context("cannot read Relay Grant file")?
        .trim()
        .to_owned();
    if grant_credential.is_empty()
        || grant_credential.len() > 512
        || grant_credential.chars().any(char::is_whitespace)
    {
        bail!("Relay Grant file contains an invalid credential");
    }
    let mut control = swarm.behaviour().streams.new_control();
    let authentication = async move {
        let mut stream = control
            .open_stream(relay_peer, StreamProtocol::new(RELAY_AUTH_PROTOCOL))
            .await
            .context("Relay does not support JLShell Grant preauthorization")?;
        write_frame(
            &mut stream,
            &RelayAuthRequest {
                grant_credential,
                agent_peer_id: agent_peer.to_bytes(),
            },
        )
        .await?;
        let response: RelayAuthResponse = read_frame(&mut stream).await?;
        if RelayAuthStatus::try_from(response.status).unwrap_or(RelayAuthStatus::Unspecified)
            != RelayAuthStatus::Ok
        {
            bail!(
                "Relay rejected Grant preauthorization: {}",
                response.message
            );
        }
        Ok(())
    };
    tokio::pin!(authentication);
    let timeout = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            result = &mut authentication => return result,
            () = &mut timeout => bail!("Relay Grant preauthorization timed out"),
            event = swarm.select_next_some() => {
                if let SwarmEvent::ConnectionClosed { peer_id, .. } = event
                    && peer_id == relay_peer
                {
                    bail!("Relay connection closed during Grant preauthorization");
                }
            }
        }
    }
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

impl TryFrom<Args> for RunArgs {
    type Error = anyhow::Error;

    fn try_from(value: Args) -> Result<Self> {
        Ok(Self {
            agent_peer: value
                .agent_peer
                .context("--agent-peer is required unless --print-identity is used")?,
            agent_addresses: value.agent_addresses,
            relay_address: value.relay_address,
            relay_peer: value.relay_peer,
            relay_grant: value.relay_grant,
            connect_policy: value.connect_policy,
            ticket: value
                .ticket
                .context("--ticket is required unless --print-identity is used")?,
            target: value
                .target
                .context("--target is required unless --print-identity is used")?,
            local_bind: value.local_bind,
        })
    }
}

fn validate_args(args: &RunArgs) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_probe_requires_no_tunnel_arguments() {
        let args = Args::try_parse_from(["jlshell-connector", "--print-identity"]).unwrap();
        assert!(args.print_identity);
        assert!(args.agent_peer.is_none());
        assert!(args.ticket.is_none());
        assert!(args.target.is_none());
    }

    #[test]
    fn tunnel_arguments_are_checked_before_startup() {
        let args = Args::try_parse_from(["jlshell-connector"]).unwrap();
        assert!(RunArgs::try_from(args).is_err());
    }
}
