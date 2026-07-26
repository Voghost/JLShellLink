use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;
use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use link_crypto::load_or_generate_identity;
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
    #[arg(long = "listen")]
    listen_addresses: Vec<Multiaddr>,
    /// Required before any non-loopback listen address is accepted.
    #[arg(long)]
    allow_public_listen: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    let identity = load_or_generate_identity(&args.identity)?;
    let peer_id = identity.public().to_peer_id();
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

fn is_loopback(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Protocol::Ip6(ip)) => IpAddr::V6(ip).is_loopback(),
        _ => false,
    }
}
