//! Shared libp2p transport assembly and TCP stream bridging.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::{
    PeerId, SwarmBuilder, autonat, dcutr, identify, identity, noise, ping, relay, tcp, yamux,
};

pub const DIRECT_DIAL_TIMEOUT_SECONDS: u64 = 3;
pub const QUIC_DIAL_PRIORITY_SECONDS: u64 = 1;
pub const IDENTIFY_PROTOCOL: &str = "/jlshell/link/identify/1.0.0";
pub const RELAY_RESERVATION_AUTH_TTL_SECONDS: i64 = 5 * 60;
pub const RELAY_RESERVATION_REFRESH_SECONDS: u64 = 2 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreauthorizedRelayGrant {
    pub grant_id: String,
    pub connector_peer_id: PeerId,
    pub agent_peer_id: PeerId,
    pub remaining_bytes: u64,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RelayGrantCacheError {
    #[error("relay grant has already been preauthorized")]
    Duplicate,
    #[error("relay grant is already expired")]
    Expired,
    #[error("relay grant has no remaining byte allowance")]
    Exhausted,
}

#[derive(Clone, Default)]
pub struct RelayGrantCache {
    inner: Arc<parking_lot::Mutex<RelayGrantCacheState>>,
}

#[derive(Default)]
struct RelayGrantCacheState {
    pending: HashMap<(PeerId, PeerId), VecDeque<PreauthorizedRelayGrant>>,
    known_grants: HashMap<String, i64>,
}

impl RelayGrantCache {
    /// Registers a validated grant and binds it to the authenticated connector peer.
    pub fn preauthorize(&self, grant: PreauthorizedRelayGrant) -> Result<(), RelayGrantCacheError> {
        self.preauthorize_at(grant, unix_epoch_seconds())
    }

    fn preauthorize_at(
        &self,
        grant: PreauthorizedRelayGrant,
        now_epoch_seconds: i64,
    ) -> Result<(), RelayGrantCacheError> {
        if grant.expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(RelayGrantCacheError::Expired);
        }
        if grant.remaining_bytes == 0 {
            return Err(RelayGrantCacheError::Exhausted);
        }
        let mut state = self.inner.lock();
        state
            .known_grants
            .retain(|_, expires_at| *expires_at > now_epoch_seconds);
        if state
            .known_grants
            .insert(grant.grant_id.clone(), grant.expires_at_epoch_seconds)
            .is_some()
        {
            return Err(RelayGrantCacheError::Duplicate);
        }
        state
            .pending
            .entry((grant.connector_peer_id, grant.agent_peer_id))
            .or_default()
            .push_back(grant);
        drop(state);
        Ok(())
    }

    fn consume_at(
        &self,
        connector_peer_id: PeerId,
        agent_peer_id: PeerId,
        now_epoch_seconds: i64,
    ) -> Option<libp2p::relay::CircuitAuthorization> {
        let mut state = self.inner.lock();
        let key = (connector_peer_id, agent_peer_id);
        let queue = state.pending.get_mut(&key)?;
        while let Some(grant) = queue.pop_front() {
            if grant.expires_at_epoch_seconds <= now_epoch_seconds || grant.remaining_bytes == 0 {
                continue;
            }
            let seconds = u64::try_from(grant.expires_at_epoch_seconds - now_epoch_seconds).ok()?;
            let authorization = libp2p::relay::CircuitAuthorization {
                id: grant.grant_id,
                max_circuit_bytes: grant.remaining_bytes,
                max_circuit_duration: Duration::from_secs(seconds),
            };
            if queue.is_empty() {
                state.pending.remove(&key);
            }
            return Some(authorization);
        }
        state.pending.remove(&key);
        None
    }
}

impl libp2p::relay::CircuitAuthorizer for RelayGrantCache {
    fn authorize(
        &mut self,
        src_peer_id: PeerId,
        dst_peer_id: PeerId,
    ) -> Option<libp2p::relay::CircuitAuthorization> {
        self.consume_at(src_peer_id, dst_peer_id, unix_epoch_seconds())
    }
}

#[derive(Clone, Default)]
pub struct RelayReservationCache {
    authorized: Arc<parking_lot::Mutex<HashMap<PeerId, i64>>>,
}

impl RelayReservationCache {
    /// Authorizes reservations from an authenticated Agent `PeerId` until the bounded expiry.
    pub fn preauthorize(
        &self,
        agent_peer_id: PeerId,
        expires_at_epoch_seconds: i64,
    ) -> Result<i64, RelayGrantCacheError> {
        self.preauthorize_at(
            agent_peer_id,
            expires_at_epoch_seconds,
            unix_epoch_seconds(),
        )
    }

    fn preauthorize_at(
        &self,
        agent_peer_id: PeerId,
        expires_at_epoch_seconds: i64,
        now_epoch_seconds: i64,
    ) -> Result<i64, RelayGrantCacheError> {
        let bounded_expiry = expires_at_epoch_seconds
            .min(now_epoch_seconds.saturating_add(RELAY_RESERVATION_AUTH_TTL_SECONDS));
        if bounded_expiry <= now_epoch_seconds {
            return Err(RelayGrantCacheError::Expired);
        }
        self.authorized.lock().insert(agent_peer_id, bounded_expiry);
        Ok(bounded_expiry)
    }

    fn authorize_at(&self, agent_peer_id: PeerId, now_epoch_seconds: i64) -> bool {
        let mut authorized = self.authorized.lock();
        authorized.retain(|_, expires_at| *expires_at > now_epoch_seconds);
        authorized.contains_key(&agent_peer_id)
    }
}

impl libp2p::relay::ReservationAuthorizer for RelayReservationCache {
    fn authorize(&mut self, src_peer_id: PeerId) -> bool {
        self.authorize_at(src_peer_id, unix_epoch_seconds())
    }
}

fn unix_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

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
    pub streams: libp2p_stream::Behaviour,
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

pub fn build_relay_swarm(
    identity: identity::Keypair,
    circuit_authorizer: Option<Box<dyn relay::CircuitAuthorizer>>,
    reservation_authorizer: Option<Box<dyn relay::ReservationAuthorizer>>,
) -> Result<Swarm<RelayBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(move |key| {
            let local_peer_id = key.public().to_peer_id();
            let circuit_protected = circuit_authorizer.is_some();
            let reservation_protected = reservation_authorizer.is_some();
            let default_config = relay::Config::default();
            let relay_config = relay::Config {
                circuit_authorizer,
                reservation_authorizer,
                reservation_duration: if reservation_protected {
                    Duration::from_secs(RELAY_RESERVATION_AUTH_TTL_SECONDS as u64)
                } else {
                    default_config.reservation_duration
                },
                // Each validated Grant supplies its own remaining byte allowance.
                max_circuit_bytes: if circuit_protected {
                    0
                } else {
                    default_config.max_circuit_bytes
                },
                // The one-circuit authorization supplies the effective deadline.
                max_circuit_duration: if circuit_protected {
                    Duration::from_secs(u64::from(u32::MAX))
                } else {
                    default_config.max_circuit_duration
                },
                ..default_config
            };
            RelayBehaviour {
                relay: relay::Behaviour::new(local_peer_id, relay_config),
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

/// Returns true for an exact, dialable IP TCP or QUIC Agent address.
pub fn is_advertisable_agent_address(address: &libp2p::Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;

    let protocols = address.iter().collect::<Vec<_>>();
    match protocols.as_slice() {
        [Protocol::Ip4(ip), Protocol::Tcp(port)]
        | [Protocol::Ip4(ip), Protocol::Udp(port), Protocol::QuicV1] => {
            !ip.is_unspecified() && !ip.is_multicast() && *port > 0
        }
        [Protocol::Ip6(ip), Protocol::Tcp(port)]
        | [Protocol::Ip6(ip), Protocol::Udp(port), Protocol::QuicV1] => {
            !ip.is_unspecified() && !ip.is_multicast() && *port > 0
        }
        _ => false,
    }
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

    #[test]
    fn accepts_only_exact_agent_ip_addresses() {
        assert!(is_advertisable_agent_address(
            &"/ip4/203.0.113.10/tcp/7001".parse().unwrap()
        ));
        assert!(is_advertisable_agent_address(
            &"/ip6/2001:db8::10/udp/7001/quic-v1".parse().unwrap()
        ));
        assert!(!is_advertisable_agent_address(
            &"/ip4/0.0.0.0/tcp/7001".parse().unwrap()
        ));
        assert!(!is_advertisable_agent_address(
            &"/ip4/203.0.113.10/tcp/7001/p2p-circuit".parse().unwrap()
        ));
    }

    #[test]
    fn relay_grant_is_target_bound_and_single_use() {
        let cache = RelayGrantCache::default();
        let connector = PeerId::random();
        let agent = PeerId::random();
        let other_agent = PeerId::random();
        cache
            .preauthorize_at(
                PreauthorizedRelayGrant {
                    grant_id: "grant-1".to_owned(),
                    connector_peer_id: connector,
                    agent_peer_id: agent,
                    remaining_bytes: 4096,
                    expires_at_epoch_seconds: 1_100,
                },
                1_000,
            )
            .unwrap();

        assert!(cache.consume_at(connector, other_agent, 1_001).is_none());
        let authorization = cache.consume_at(connector, agent, 1_001).unwrap();
        assert_eq!(authorization.id, "grant-1");
        assert_eq!(authorization.max_circuit_bytes, 4096);
        assert!(cache.consume_at(connector, agent, 1_002).is_none());
    }

    #[test]
    fn relay_grant_rejects_replay_expiry_and_exhaustion() {
        let cache = RelayGrantCache::default();
        let grant = PreauthorizedRelayGrant {
            grant_id: "grant-1".to_owned(),
            connector_peer_id: PeerId::random(),
            agent_peer_id: PeerId::random(),
            remaining_bytes: 1,
            expires_at_epoch_seconds: 1_100,
        };
        cache.preauthorize_at(grant.clone(), 1_000).unwrap();
        assert_eq!(
            cache.preauthorize_at(grant, 1_000),
            Err(RelayGrantCacheError::Duplicate)
        );
        let expired = PreauthorizedRelayGrant {
            grant_id: "expired".to_owned(),
            expires_at_epoch_seconds: 1_000,
            ..PreauthorizedRelayGrant {
                grant_id: String::new(),
                connector_peer_id: PeerId::random(),
                agent_peer_id: PeerId::random(),
                remaining_bytes: 1,
                expires_at_epoch_seconds: 0,
            }
        };
        assert_eq!(
            cache.preauthorize_at(expired, 1_000),
            Err(RelayGrantCacheError::Expired)
        );
    }

    #[test]
    fn relay_reservation_authorization_is_peer_bound_and_bounded() {
        let cache = RelayReservationCache::default();
        let agent = PeerId::random();
        let other = PeerId::random();
        cache.preauthorize_at(agent, 10_000, 1_000).unwrap();

        assert!(cache.authorize_at(agent, 1_299));
        assert!(!cache.authorize_at(other, 1_299));
        assert!(!cache.authorize_at(agent, 1_300));
    }
}
