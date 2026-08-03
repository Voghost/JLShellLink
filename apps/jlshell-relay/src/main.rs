use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::StreamProtocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use link_control_plane::{
    ControlPlaneClient, RelayUsageReport, ValidatedRelayAgent, ValidatedRelayGrant,
    read_node_credential,
};
use link_crypto::{load_or_generate_identity, sign_identity_payload};
use link_protocol::{
    RELAY_AUTH_PROTOCOL, RELAY_RESERVATION_AUTH_PROTOCOL, RelayAuthRequest, RelayAuthResponse,
    RelayAuthStatus, RelayReservationAuthRequest, RelayReservationAuthResponse,
    RelayReservationAuthStatus, read_frame, write_frame,
};
use link_transport::{
    PreauthorizedRelayGrant, RELAY_RESERVATION_AUTH_TTL_SECONDS, RelayGrantCache,
    RelayReservationCache,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

#[derive(Clone)]
struct RelayControlPlane {
    client: ControlPlaneClient,
    credential: String,
    usage_tx: tokio::sync::mpsc::UnboundedSender<UsageUpdate>,
}

#[derive(Debug)]
struct UsageUpdate {
    grant_id: String,
    uploaded_bytes: u64,
    downloaded_bytes: u64,
    closed: bool,
}

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
    let control_plane = start_control_plane(&args)?;
    let addresses = if args.listen_addresses.is_empty() {
        vec![
            "/ip4/127.0.0.1/tcp/4001".parse()?,
            "/ip4/127.0.0.1/udp/4001/quic-v1".parse()?,
        ]
    } else {
        args.listen_addresses.clone()
    };

    validate_listen_security(&args, &addresses, control_plane.is_some())?;
    if args.allow_public_listen {
        warn!("public relay enabled for an unsigned, non-production prototype");
    }

    run_relay(identity, addresses, peer_id, control_plane).await
}

async fn run_relay(
    identity: libp2p::identity::Keypair,
    addresses: Vec<Multiaddr>,
    peer_id: PeerId,
    control_plane: Option<RelayControlPlane>,
) -> Result<()> {
    let grant_cache = RelayGrantCache::default();
    let reservation_cache = RelayReservationCache::default();
    let circuit_authorizer = control_plane
        .as_ref()
        .map(|_| Box::new(grant_cache.clone()) as Box<dyn libp2p::relay::CircuitAuthorizer>);
    let reservation_authorizer = control_plane.as_ref().map(|_| {
        Box::new(reservation_cache.clone()) as Box<dyn libp2p::relay::ReservationAuthorizer>
    });
    let mut swarm =
        link_transport::build_relay_swarm(identity, circuit_authorizer, reservation_authorizer)?;
    let mut relay_auth = swarm
        .behaviour()
        .streams
        .new_control()
        .accept(StreamProtocol::new(RELAY_AUTH_PROTOCOL))
        .context("Relay auth protocol is already registered")?;
    let mut reservation_auth = swarm
        .behaviour()
        .streams
        .new_control()
        .accept(StreamProtocol::new(RELAY_RESERVATION_AUTH_PROTOCOL))
        .context("Relay reservation auth protocol is already registered")?;
    for address in addresses {
        swarm.listen_on(address)?;
    }
    println!("RELAY_PEER_ID={peer_id}");

    loop {
        tokio::select! {
            incoming = reservation_auth.next() => {
                let Some((agent_peer, stream)) = incoming else {
                    bail!("Relay reservation auth listener stopped unexpectedly");
                };
                let control_plane = control_plane.clone();
                let reservation_cache = reservation_cache.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_reservation_auth(
                        agent_peer,
                        stream,
                        control_plane,
                        reservation_cache,
                    ).await {
                        warn!(%agent_peer, %error, "Relay reservation preauthorization failed");
                    }
                });
            }
            incoming = relay_auth.next() => {
                let Some((connector_peer, stream)) = incoming else {
                    bail!("Relay auth protocol listener stopped unexpectedly");
                };
                let control_plane = control_plane.clone();
                let grant_cache = grant_cache.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_relay_auth(
                        connector_peer,
                        stream,
                        control_plane,
                        grant_cache,
                    ).await {
                        warn!(%connector_peer, %error, "Relay Grant preauthorization failed");
                    }
                });
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("LISTEN_ADDRESS={address}/p2p/{peer_id}");
                    // Circuit Relay v2 reservations must advertise at least one reachable
                    // relay address. For the prototype the configured listen address is the
                    // explicit advertised address (loopback unless the operator opts in).
                    swarm.add_external_address(address);
                }
                SwarmEvent::Behaviour(link_transport::RelayBehaviourEvent::Relay(
                    libp2p::relay::Event::CircuitUsage {
                        authorization_id,
                        uploaded_bytes,
                        downloaded_bytes,
                        ..
                    }
                )) => {
                    send_usage(control_plane.as_ref(), authorization_id, uploaded_bytes, downloaded_bytes, false);
                }
                SwarmEvent::Behaviour(link_transport::RelayBehaviourEvent::Relay(
                    libp2p::relay::Event::CircuitClosed {
                        authorization_id: Some(authorization_id),
                        uploaded_bytes,
                        downloaded_bytes,
                        ..
                    }
                )) => {
                    send_usage(control_plane.as_ref(), authorization_id, uploaded_bytes, downloaded_bytes, true);
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

fn start_control_plane(args: &Args) -> Result<Option<RelayControlPlane>> {
    let Some(base_url) = &args.control_plane_url else {
        if args.credential_file.is_some() {
            bail!("--credential-file requires --control-plane-url");
        }
        return Ok(None);
    };
    let credential = read_node_credential(
        args.credential_file
            .as_ref()
            .context("--credential-file is required with --control-plane-url")?,
    )?;
    let client = ControlPlaneClient::new(base_url)?;
    let (usage_tx, usage_rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = RelayControlPlane {
        client: client.clone(),
        credential: credential.clone(),
        usage_tx,
    };
    let seconds = args.heartbeat_seconds;
    let heartbeat_client = client.clone();
    let heartbeat_credential = credential.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(seconds));
        loop {
            interval.tick().await;
            if let Err(error) = heartbeat_client
                .relay_heartbeat(&heartbeat_credential, env!("CARGO_PKG_VERSION"))
                .await
            {
                warn!(%error, "Relay control-plane heartbeat failed");
            }
        }
    });
    tokio::spawn(report_usage(client, credential, usage_rx));
    Ok(Some(runtime))
}

async fn handle_relay_auth(
    connector_peer: PeerId,
    mut stream: libp2p::swarm::Stream,
    control_plane: Option<RelayControlPlane>,
    grant_cache: RelayGrantCache,
) -> Result<()> {
    let request: RelayAuthRequest = read_frame(&mut stream).await?;
    let response =
        match process_relay_auth(connector_peer, request, control_plane, &grant_cache).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%connector_peer, %error, "Relay Grant rejected");
                RelayAuthResponse {
                    status: RelayAuthStatus::Unauthorized.into(),
                    message: "Relay Grant was rejected".to_owned(),
                    grant_id: String::new(),
                    remaining_bytes: 0,
                    expires_at_epoch_seconds: 0,
                }
            }
        };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

async fn process_relay_auth(
    connector_peer: PeerId,
    request: RelayAuthRequest,
    control_plane: Option<RelayControlPlane>,
    grant_cache: &RelayGrantCache,
) -> Result<RelayAuthResponse> {
    let control_plane = control_plane.context("Relay is not connected to its control plane")?;
    let requested_agent = PeerId::from_bytes(&request.agent_peer_id)
        .context("request contains an invalid Agent PeerId")?;
    let validated = control_plane
        .client
        .validate_relay_grant(&control_plane.credential, &request.grant_credential)
        .await?;
    validate_grant_target(requested_agent, &validated)?;
    let expires_at = OffsetDateTime::parse(&validated.expires_at, &Rfc3339)
        .context("control plane returned an invalid Grant expiry")?
        .unix_timestamp();
    let remaining_bytes = validated.byte_limit.saturating_sub(validated.used_bytes);
    grant_cache.preauthorize(PreauthorizedRelayGrant {
        grant_id: validated.grant_id.clone(),
        connector_peer_id: connector_peer,
        agent_peer_id: requested_agent,
        remaining_bytes,
        expires_at_epoch_seconds: expires_at,
    })?;
    Ok(RelayAuthResponse {
        status: RelayAuthStatus::Ok.into(),
        message: "Relay Grant accepted for one circuit".to_owned(),
        grant_id: validated.grant_id,
        remaining_bytes,
        expires_at_epoch_seconds: expires_at,
    })
}

async fn handle_reservation_auth(
    agent_peer: PeerId,
    mut stream: libp2p::swarm::Stream,
    control_plane: Option<RelayControlPlane>,
    reservation_cache: RelayReservationCache,
) -> Result<()> {
    let request: RelayReservationAuthRequest = read_frame(&mut stream).await?;
    let response = match process_reservation_auth(
        agent_peer,
        request,
        control_plane,
        &reservation_cache,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            warn!(%agent_peer, %error, "Relay Agent reservation rejected");
            RelayReservationAuthResponse {
                status: RelayReservationAuthStatus::Unauthorized.into(),
                message: "Agent reservation was rejected".to_owned(),
                agent_id: String::new(),
                authorization_expires_at_epoch_seconds: 0,
            }
        }
    };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

async fn process_reservation_auth(
    agent_peer: PeerId,
    request: RelayReservationAuthRequest,
    control_plane: Option<RelayControlPlane>,
    reservation_cache: &RelayReservationCache,
) -> Result<RelayReservationAuthResponse> {
    let control_plane = control_plane.context("Relay is not connected to its control plane")?;
    let validated = control_plane
        .client
        .validate_relay_agent(&control_plane.credential, &request.agent_credential)
        .await?;
    validate_agent_peer(agent_peer, &validated)?;
    let credential_expires_at = validated.credential_expires_at.as_deref().map_or_else(
        || {
            Ok::<_, anyhow::Error>(
                OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .saturating_add(RELAY_RESERVATION_AUTH_TTL_SECONDS),
            )
        },
        |expires_at| {
            OffsetDateTime::parse(expires_at, &Rfc3339)
                .context("control plane returned an invalid Agent credential expiry")
                .map(OffsetDateTime::unix_timestamp)
        },
    )?;
    let authorization_expires_at =
        reservation_cache.preauthorize(agent_peer, credential_expires_at)?;
    Ok(RelayReservationAuthResponse {
        status: RelayReservationAuthStatus::Ok.into(),
        message: "Agent reservations authorized for a bounded lease".to_owned(),
        agent_id: validated.agent_id,
        authorization_expires_at_epoch_seconds: authorization_expires_at,
    })
}

fn validate_agent_peer(agent_peer: PeerId, validated: &ValidatedRelayAgent) -> Result<()> {
    let registered_peer: PeerId = validated
        .agent_peer_id
        .parse()
        .context("control plane returned an invalid Agent PeerId")?;
    if registered_peer != agent_peer {
        bail!("Agent credential does not belong to the authenticated PeerId");
    }
    Ok(())
}

fn validate_grant_target(requested_agent: PeerId, validated: &ValidatedRelayGrant) -> Result<()> {
    let granted_agent: PeerId = validated
        .agent_peer_id
        .parse()
        .context("control plane returned an invalid Agent PeerId")?;
    if granted_agent != requested_agent {
        bail!("Relay Grant target does not match the requested Agent");
    }
    Ok(())
}

fn send_usage(
    control_plane: Option<&RelayControlPlane>,
    grant_id: String,
    uploaded_bytes: u64,
    downloaded_bytes: u64,
    closed: bool,
) {
    let Some(control_plane) = control_plane else {
        return;
    };
    if let Err(error) = control_plane.usage_tx.send(UsageUpdate {
        grant_id,
        uploaded_bytes,
        downloaded_bytes,
        closed,
    }) {
        warn!(%error, "Relay usage reporter stopped");
    }
}

async fn report_usage(
    client: ControlPlaneClient,
    credential: String,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<UsageUpdate>,
) {
    let mut sequences = std::collections::HashMap::<String, u64>::new();
    while let Some(update) = updates.recv().await {
        let sequence = sequences.entry(update.grant_id.clone()).or_default();
        *sequence = sequence.saturating_add(1);
        if let Err(error) = report_usage_with_retry(&client, &credential, &update, *sequence).await
        {
            warn!(grant_id = %update.grant_id, %error, "Relay usage report failed");
        }
        if update.closed {
            sequences.remove(&update.grant_id);
        }
    }
}

async fn report_usage_with_retry(
    client: &ControlPlaneClient,
    credential: &str,
    update: &UsageUpdate,
    sequence: u64,
) -> Result<()> {
    let mut last_error = None;
    for attempt in 0..3_u64 {
        let report = RelayUsageReport {
            grant_id: &update.grant_id,
            sequence,
            uploaded_bytes: update.uploaded_bytes,
            downloaded_bytes: update.downloaded_bytes,
            closed: update.closed,
        };
        match client.report_relay_usage(credential, &report).await {
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
    }
    Err(last_error.expect("at least one Relay usage report attempt is made"))
}

fn is_loopback(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Protocol::Ip6(ip)) => IpAddr::V6(ip).is_loopback(),
        _ => false,
    }
}

fn validate_listen_security(
    args: &Args,
    addresses: &[Multiaddr],
    has_control_plane: bool,
) -> Result<()> {
    if args.allow_public_listen && !has_control_plane {
        bail!("public Relay requires --control-plane-url and --credential-file");
    }
    if !args.allow_public_listen {
        for address in addresses {
            if !is_loopback(address) {
                bail!(
                    "refusing public listen address {address}; pass --allow-public-listen to acknowledge this unsigned prototype"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_target_must_match_requested_agent() {
        let requested_agent = PeerId::random();
        let mut grant = ValidatedRelayGrant {
            grant_id: "grant-1".to_owned(),
            user_id: "user-1".to_owned(),
            relay_id: "relay-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            agent_peer_id: requested_agent.to_string(),
            byte_limit: 1024,
            used_bytes: 0,
            expires_at: "2030-01-01T00:00:00Z".to_owned(),
        };
        validate_grant_target(requested_agent, &grant).unwrap();
        grant.agent_peer_id = PeerId::random().to_string();
        assert!(validate_grant_target(requested_agent, &grant).is_err());
    }

    #[test]
    fn agent_credential_must_match_authenticated_peer() {
        let agent_peer = PeerId::random();
        let mut agent = ValidatedRelayAgent {
            agent_id: "agent-id".to_owned(),
            user_id: "user-id".to_owned(),
            agent_peer_id: agent_peer.to_string(),
            credential_expires_at: Some("2030-01-01T00:00:00Z".to_owned()),
        };
        validate_agent_peer(agent_peer, &agent).unwrap();
        agent.agent_peer_id = PeerId::random().to_string();
        assert!(validate_agent_peer(agent_peer, &agent).is_err());
    }

    #[test]
    fn public_relay_requires_control_plane_arguments() {
        let args = Args::try_parse_from([
            "jlshell-relay",
            "--allow-public-listen",
            "--listen",
            "/ip4/0.0.0.0/tcp/4001",
        ])
        .unwrap();
        assert!(validate_listen_security(&args, &args.listen_addresses, false).is_err());
    }
}
