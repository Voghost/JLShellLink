//! Shared libp2p transport assembly and TCP stream bridging.

use std::time::Duration;

use anyhow::Result;
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::{
    PeerId, SwarmBuilder, autonat, dcutr, identify, identity, noise, ping, relay, tcp, yamux,
};

pub const DIRECT_DIAL_TIMEOUT_SECONDS: u64 = 3;
pub const QUIC_DIAL_PRIORITY_SECONDS: u64 = 1;
pub const IDENTIFY_PROTOCOL: &str = "/jlshell/link/identify/1.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum ConnectPolicy {
    Auto,
    DirectOnly,
    RelayOnly,
}

#[derive(NetworkBehaviour)]
pub struct ClientBehaviour {
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub streams: libp2p_stream::Behaviour,
}

#[derive(NetworkBehaviour)]
pub struct RelayBehaviour {
    pub relay: relay::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

pub fn build_client_swarm(identity: identity::Keypair) -> Result<Swarm<ClientBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let local_peer_id = key.public().to_peer_id();
            ClientBehaviour {
                relay_client,
                dcutr: dcutr::Behaviour::new(local_peer_id),
                autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                identify: identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL.to_owned(),
                    key.public(),
                )),
                ping: ping::Behaviour::new(ping::Config::new()),
                streams: libp2p_stream::Behaviour::new(),
            }
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_mins(2)))
        .build();
    Ok(swarm)
}

pub fn build_relay_swarm(identity: identity::Keypair) -> Result<Swarm<RelayBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            let local_peer_id = key.public().to_peer_id();
            RelayBehaviour {
                relay: relay::Behaviour::new(local_peer_id, relay::Config::default()),
                identify: identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL.to_owned(),
                    key.public(),
                )),
                ping: ping::Behaviour::new(ping::Config::new()),
            }
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_mins(2)))
        .build();
    Ok(swarm)
}

pub fn is_relay_address(address: &libp2p::Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2pCircuit))
}

#[must_use]
pub fn is_quic_address(address: &libp2p::Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::QuicV1))
}

pub fn relay_circuit_address(
    relay_address: &libp2p::Multiaddr,
    relay_peer_id: PeerId,
    destination_peer_id: Option<PeerId>,
) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;

    let mut address = relay_address.clone();
    if !address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_)))
    {
        address.push(Protocol::P2p(relay_peer_id));
    }
    address.push(Protocol::P2pCircuit);
    if let Some(destination) = destination_peer_id {
        address.push(Protocol::P2p(destination));
    }
    address
}

pub fn ensure_expected_peer(address: &mut libp2p::Multiaddr, peer_id: PeerId) {
    use libp2p::multiaddr::Protocol;

    let already_ends_with_peer =
        matches!(address.iter().last(), Some(Protocol::P2p(existing)) if existing == peer_id);
    if !already_ends_with_peer {
        address.push(Protocol::P2p(peer_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_relay_circuit_address() {
        let relay_peer = PeerId::random();
        let agent_peer = PeerId::random();
        let base: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let address = relay_circuit_address(&base, relay_peer, Some(agent_peer));
        assert!(is_relay_address(&address));
        assert!(address.to_string().ends_with(&format!("/p2p/{agent_peer}")));
    }

    #[test]
    fn recognizes_quic_address() {
        let address: libp2p::Multiaddr = "/ip4/127.0.0.1/udp/7001/quic-v1".parse().unwrap();
        assert!(is_quic_address(&address));
    }
}
