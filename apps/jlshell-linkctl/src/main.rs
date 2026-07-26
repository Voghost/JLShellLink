use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use libp2p::PeerId;
use link_crypto::{
    TicketRequest, generate_authority, generate_identity, issue_ticket, load_authority_private,
    save_authority_private, save_authority_public, save_identity,
};
use prost::Message;

#[derive(Debug, Parser)]
#[command(
    name = "jlshell-linkctl",
    version,
    about = "JLShell Link development key and ticket tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a development Ed25519 ticket authority.
    AuthorityInit {
        #[arg(long, default_value = "authority-private.json")]
        private_key: PathBuf,
        #[arg(long, default_value = "authority-public.json")]
        public_key: PathBuf,
    },
    /// Create a persistent libp2p Ed25519 identity.
    IdentityInit {
        #[arg(long)]
        output: PathBuf,
    },
    /// Issue a short-lived, one-stream ticket for one exact IP and port.
    TicketIssue {
        #[arg(long)]
        authority_private: PathBuf,
        #[arg(long)]
        connector_peer: PeerId,
        #[arg(long)]
        agent_peer: PeerId,
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::AuthorityInit {
            private_key,
            public_key,
        } => {
            let key = generate_authority();
            save_authority_private(&private_key, &key)?;
            save_authority_public(&public_key, &key.verifying_key())?;
            println!("AUTHORITY_PRIVATE={}", private_key.display());
            println!("AUTHORITY_PUBLIC={}", public_key.display());
        }
        Command::IdentityInit { output } => {
            let identity = generate_identity();
            let peer_id = identity.public().to_peer_id();
            save_identity(&output, &identity)?;
            println!("PEER_ID={peer_id}");
            println!("IDENTITY={}", output.display());
        }
        Command::TicketIssue {
            authority_private,
            connector_peer,
            agent_peer,
            target,
            ttl_seconds,
            output,
        } => {
            if ttl_seconds == 0 {
                bail!("--ttl-seconds must be greater than zero");
            }
            let authority = load_authority_private(&authority_private)?;
            let request = TicketRequest {
                connector_peer_id: connector_peer,
                agent_peer_id: agent_peer,
                target_ip: target.ip(),
                target_port: target.port(),
                now_epoch_seconds: now_epoch_seconds()?,
                ttl_seconds,
            };
            let ticket = issue_ticket(&authority, &request);
            write_ticket(&output, &ticket.encode_to_vec())?;
            println!("TICKET={}", output.display());
            println!("EXPIRES_IN_SECONDS={ttl_seconds}");
        }
    }
    Ok(())
}

fn now_epoch_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system clock value is too large")
}

fn write_ticket(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create ticket {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
