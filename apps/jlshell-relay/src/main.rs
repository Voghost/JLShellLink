use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use link_control_plane::{ControlPlaneClient, read_node_credential};
use link_crypto::{load_or_generate_identity, sign_identity_payload};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(
    name = "jlshell-relay",
    version,
    about = "NON-PRODUCTION JLShell Link relay prototype"
)]
struct Args {
    #[arg(long, default_value = "relay-identity.key")]
    identity: PathBuf,
    #[arg(long)]
    print_identity: bool,
    #[arg(long, conflicts_with = "print_identity")]
    identity_proof: Option<String>,
    #[arg(long = "listen")]
    listen_addresses: Vec<Multiaddr>,
    /// Required before any non-loopback listen address is accepted.
    #[arg(long)]
    allow_public_listen: bool,
    #[arg(long)]
    control_plane_url: Option<String>,
    #[arg(long, requires = "control_plane_url")]
    credential_file: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(10..=3600))]
    heartbeat_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    let identity = load_or_generate_identity(&args.identity)?;
    let peer_id = identity.public().to_peer_id();
    if args.print_identity || args.identity_proof.is_some() {
        let public_key = identity
            .public()
            .try_into_ed25519()
            .context("Relay identity is not Ed25519")?;
        println!("RELAY_PEER_ID={peer_id}");
        println!(
            "RELAY_PUBLIC_KEY={}",
            URL_SAFE_NO_PAD.encode(public_key.to_bytes())
        );
        if let Some(payload) = &args.identity_proof {
            let payload = URL_SAFE_NO_PAD
                .decode(payload)
                .context("--identity-proof must be base64url encoded")?;
            println!(
                "RELAY_PROOF_SIGNATURE={}",
                URL_SAFE_NO_PAD.encode(sign_identity_payload(&identity, &payload)?)
            );
        }
        println!("RELAY_EVENT=IDENTITY_READY");
        return Ok(());
    }
    start_control_plane(&args)?;
    let addresses = if args.listen_addresses.is_empty() {
        vec![
            "/ip4/127.0.0.1/tcp/4001".parse()?,
            "/ip4/127.0.0.1/udp/4001/quic-v1".parse()?,
        ]
    } else {
        args.listen_addresses
    };

    if args.allow_public_listen {
        warn!("public relay enabled for an unsigned, non-production prototype");
    } else {
        for address in &addresses {
            if !is_loopback(address) {
                bail!(
                    "refusing public listen address {address}; pass --allow-public-listen to acknowledge this unsigned prototype"
                );
            }
        }
    }

    let mut swarm = link_transport::build_relay_swarm(identity)?;
    for address in addresses {
        swarm.listen_on(address)?;
    }
    println!("RELAY_PEER_ID={peer_id}");

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("LISTEN_ADDRESS={address}/p2p/{peer_id}");
                    // Circuit Relay v2 reservations must advertise at least one reachable
                    // relay address. For the prototype the configured listen address is the
                    // explicit advertised address (loopback unless the operator opts in).
                    swarm.add_external_address(address);
                }
                SwarmEvent::Behaviour(event) => info!(?event, "relay event"),
                _ => {}
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

fn start_control_plane(args: &Args) -> Result<()> {
    let Some(base_url) = &args.control_plane_url else {
        if args.credential_file.is_some() {
            bail!("--credential-file requires --control-plane-url");
        }
        return Ok(());
    };
    let credential = read_node_credential(
        args.credential_file
            .as_ref()
            .context("--credential-file is required with --control-plane-url")?,
    )?;
    let client = ControlPlaneClient::new(base_url)?;
    let seconds = args.heartbeat_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(seconds));
        loop {
            interval.tick().await;
            if let Err(error) = client
                .relay_heartbeat(&credential, env!("CARGO_PKG_VERSION"))
                .await
            {
                warn!(%error, "Relay control-plane heartbeat failed");
            }
        }
    });
    Ok(())
}

fn is_loopback(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Protocol::Ip6(ip)) => IpAddr::V6(ip).is_loopback(),
        _ => false,
    }
}
