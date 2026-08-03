use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    OpenStatus, OpenTcpRequest, OpenTcpResponse, RELAY_RESERVATION_AUTH_PROTOCOL,
    RelayReservationAuthRequest, RelayReservationAuthResponse, RelayReservationAuthStatus,
    TCP_PROTOCOL, read_frame, write_frame,
};
use link_transport::{
    ConnectPolicy, RELAY_RESERVATION_REFRESH_SECONDS, ensure_expected_peer,
    is_advertisable_agent_address, relay_circuit_address,
};
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
    /// Exact public/private IP multiaddrs advertised to the Website for direct dialing.
    #[arg(long = "advertise")]
    advertise_addresses: Vec<Multiaddr>,
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
    /// Internal Windows SCM wrapper mode. Installed by the JLShell Link plugin.
    #[cfg(windows)]
    #[arg(long, hide = true)]
    windows_service: bool,
}

struct Authorization {
    authority_keys: tokio::sync::RwLock<AuthorityKeyring>,
    agent_peer_id: PeerId,
    allowed_targets: HashSet<SocketAddr>,
    replay_cache: NonceReplayCache,
}

#[derive(Clone)]
struct AgentControlPlane {
    credential: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    #[cfg(windows)]
    if args.windows_service {
        windows_service_host::run()?;
        return Ok(());
    }
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
    let reachable_addresses = Arc::new(tokio::sync::RwLock::new(
        args.advertise_addresses
            .iter()
            .map(|address| {
                if !is_advertisable_agent_address(address) {
                    bail!("--advertise must be an exact IP TCP or QUIC multiaddr");
                }
                Ok(address.to_string())
            })
            .collect::<Result<BTreeSet<_>>>()?,
    ));

    let mut swarm = link_transport::build_client_swarm(identity)?;
    let mut incoming = swarm
        .behaviour()
        .streams
        .new_control()
        .accept(StreamProtocol::new(TCP_PROTOCOL))
        .context("TCP stream protocol is already registered")?;

    let control_plane = start_control_plane(
        &args,
        Arc::clone(&authorization),
        Arc::clone(&reachable_addresses),
    )?;
    prepare_relay_reservation(&mut swarm, &args, control_plane.as_ref()).await?;
    configure_listeners(&mut swarm, &args, agent_peer_id)?;
    let mut reservation_refresh =
        tokio::time::interval(Duration::from_secs(RELAY_RESERVATION_REFRESH_SECONDS));
    reservation_refresh.tick().await;

    println!("AGENT_PEER_ID={agent_peer_id}");
    loop {
        tokio::select! {
            _ = reservation_refresh.tick() => {
                if let Err(error) = refresh_relay_reservation(
                    &mut swarm, &args, control_plane.as_ref(),
                ).await {
                    warn!(%error, "Relay reservation authorization refresh failed");
                }
            }
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
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if is_advertisable_agent_address(&address) {
                            reachable_addresses.write().await.insert(address.to_string());
                        }
                        println!("LISTEN_ADDRESS={address}");
                    }
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

async fn prepare_relay_reservation(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    args: &Args,
    control_plane: Option<&AgentControlPlane>,
) -> Result<()> {
    if args.relay_address.is_some() && control_plane.is_none() {
        warn!(
            "no Agent credential supplied; only an explicitly unauthenticated loopback Relay can accept the reservation"
        );
        return Ok(());
    }
    refresh_relay_reservation(swarm, args, control_plane).await
}

async fn refresh_relay_reservation(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    args: &Args,
    control_plane: Option<&AgentControlPlane>,
) -> Result<()> {
    let (Some(relay_address), Some(relay_peer), Some(control_plane)) =
        (args.relay_address.as_ref(), args.relay_peer, control_plane)
    else {
        return Ok(());
    };
    authenticate_relay_reservation(swarm, relay_address, relay_peer, &control_plane.credential)
        .await
}

fn configure_listeners(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    args: &Args,
    agent_peer_id: PeerId,
) -> Result<()> {
    if args.connect_policy != ConnectPolicy::RelayOnly {
        let listen_addresses = if args.listen_addresses.is_empty() {
            vec![
                "/ip4/127.0.0.1/tcp/7001".parse()?,
                "/ip4/127.0.0.1/udp/7001/quic-v1".parse()?,
            ]
        } else {
            args.listen_addresses.clone()
        };
        for address in listen_addresses {
            swarm.listen_on(address)?;
        }
    }
    if args.connect_policy == ConnectPolicy::DirectOnly {
        return Ok(());
    }
    if let (Some(relay_address), Some(relay_peer)) = (&args.relay_address, args.relay_peer) {
        swarm.listen_on(relay_circuit_address(
            relay_address,
            relay_peer,
            Some(agent_peer_id),
        ))?;
    } else if args.connect_policy == ConnectPolicy::RelayOnly {
        bail!("relay-only requires --relay-address and --relay-peer");
    } else {
        warn!("auto policy has no relay configured; only direct connections are available");
    }
    Ok(())
}

async fn authenticate_relay_reservation(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    relay_address: &Multiaddr,
    relay_peer: PeerId,
    agent_credential: &str,
) -> Result<()> {
    if !swarm.is_connected(&relay_peer) {
        let mut direct_address = relay_address.clone();
        ensure_expected_peer(&mut direct_address, relay_peer);
        swarm
            .dial(direct_address.clone())
            .with_context(|| format!("cannot dial Relay {direct_address}"))?;
        wait_for_relay(swarm, relay_peer).await?;
    }

    let mut control = swarm.behaviour().streams.new_control();
    let agent_credential = agent_credential.to_owned();
    let authentication = async move {
        let mut stream = control
            .open_stream(
                relay_peer,
                StreamProtocol::new(RELAY_RESERVATION_AUTH_PROTOCOL),
            )
            .await
            .context("Relay does not support Agent reservation authorization")?;
        write_frame(
            &mut stream,
            &RelayReservationAuthRequest { agent_credential },
        )
        .await?;
        let response: RelayReservationAuthResponse = read_frame(&mut stream).await?;
        if RelayReservationAuthStatus::try_from(response.status)
            .unwrap_or(RelayReservationAuthStatus::Unspecified)
            != RelayReservationAuthStatus::Ok
        {
            bail!("Relay rejected Agent reservation: {}", response.message);
        }
        Ok(())
    };
    tokio::pin!(authentication);
    let timeout = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            result = &mut authentication => return result,
            () = &mut timeout => bail!("Relay reservation authorization timed out"),
            event = swarm.select_next_some() => {
                if let SwarmEvent::ConnectionClosed { peer_id, .. } = event
                    && peer_id == relay_peer
                {
                    bail!("Relay connection closed during reservation authorization");
                }
            }
        }
    }
}

async fn wait_for_relay(
    swarm: &mut libp2p::Swarm<link_transport::ClientBehaviour>,
    relay_peer: PeerId,
) -> Result<()> {
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer => {
                return Ok(());
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } if peer_id == relay_peer => bail!("cannot connect to Relay {peer_id}: {error}"),
            _ => {}
        }
    }
}

#[cfg(windows)]
mod windows_service_host {
    use std::ffi::OsString;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::service_dispatcher;

    const SERVICE_NAME: &str = "JLShellLinkAgent";
    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("cannot start Windows service dispatcher")
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            eprintln!("JLShell Link Windows service failed: {error:#}");
        }
    }

    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let handler = move |control| match control {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status = service_control_handler::register(SERVICE_NAME, handler)
            .context("cannot register Windows service control handler")?;
        set_status(
            &status,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
        )?;

        let executable = std::env::current_exe().context("cannot locate Agent executable")?;
        let arguments = std::env::args_os()
            .skip(1)
            .filter(|argument| argument != "--windows-service")
            .collect::<Vec<_>>();
        let mut child = Command::new(executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("cannot start Agent worker process")?;
        set_status(
            &status,
            ServiceState::Running,
            ServiceControlAccept::STOP,
            ServiceExitCode::Win32(0),
            0,
        )?;

        let mut unexpected_exit = false;
        loop {
            if shutdown_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                set_status(
                    &status,
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::Win32(0),
                    1,
                )?;
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            if child.try_wait()?.is_some() {
                unexpected_exit = true;
                break;
            }
        }
        set_status(
            &status,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            if unexpected_exit {
                ServiceExitCode::ServiceSpecific(1)
            } else {
                ServiceExitCode::Win32(0)
            },
            0,
        )?;
        Ok(())
    }

    fn set_status(
        handle: &ServiceStatusHandle,
        state: ServiceState,
        accepted: ServiceControlAccept,
        exit_code: ServiceExitCode,
        checkpoint: u32,
    ) -> Result<()> {
        handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accepted,
                exit_code,
                checkpoint,
                wait_hint: Duration::from_secs(if checkpoint == 0 { 0 } else { 10 }),
                process_id: None,
            })
            .context("cannot report Windows service status")
    }
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

fn start_control_plane(
    args: &Args,
    authorization: Arc<Authorization>,
    reachable_addresses: Arc<tokio::sync::RwLock<BTreeSet<String>>>,
) -> Result<Option<AgentControlPlane>> {
    let Some(base_url) = &args.control_plane_url else {
        if args.credential_file.is_some() {
            bail!("--credential-file requires --control-plane-url");
        }
        return Ok(None);
    };
    let credential_path = args
        .credential_file
        .as_ref()
        .context("--credential-file is required with --control-plane-url")?;
    let credential = read_node_credential(credential_path)?;
    let client = ControlPlaneClient::new(base_url)?;
    let runtime = AgentControlPlane {
        credential: credential.clone(),
    };
    let seconds = args.heartbeat_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(seconds));
        loop {
            interval.tick().await;
            let addresses = reachable_addresses
                .read()
                .await
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            if let Err(error) = client
                .agent_heartbeat(&credential, env!("CARGO_PKG_VERSION"), &addresses)
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
    Ok(Some(runtime))
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
