use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use libp2p::{PeerId, identity};
use link_protocol::{PROTOCOL_VERSION, SignedTicket, TicketClaims};
use parking_lot::Mutex;
use prost::Message;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const NONCE_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key file: {0}")]
    InvalidKey(String),
    #[error("secret file permissions must be 0600: {0}")]
    InsecurePermissions(String),
    #[error("invalid ticket: {0}")]
    InvalidTicket(String),
    #[error("ticket signature is invalid")]
    InvalidSignature,
    #[error("ticket is not valid yet")]
    NotYetValid,
    #[error("ticket has expired")]
    Expired,
    #[error("ticket does not authorize this connector")]
    WrongConnector,
    #[error("ticket does not authorize this agent")]
    WrongAgent,
    #[error("ticket does not authorize target {0}:{1}")]
    WrongTarget(IpAddr, u16),
    #[error("ticket nonce was already used")]
    Replay,
}

#[derive(Clone, Debug)]
pub struct TicketRequest {
    pub connector_peer_id: PeerId,
    pub agent_peer_id: PeerId,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub now_epoch_seconds: i64,
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct VerificationContext {
    pub connector_peer_id: PeerId,
    pub agent_peer_id: PeerId,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub now_epoch_seconds: i64,
}

#[derive(Default)]
pub struct NonceReplayCache {
    entries: Mutex<HashMap<Vec<u8>, i64>>,
}

impl NonceReplayCache {
    pub fn check_and_record(&self, claims: &TicketClaims, now: i64) -> Result<(), CryptoError> {
        let mut entries = self.entries.lock();
        entries.retain(|_, expires_at| *expires_at >= now);
        if entries.contains_key(&claims.nonce) {
            return Err(CryptoError::Replay);
        }
        entries.insert(claims.nonce.clone(), claims.expires_at_epoch_seconds);
        drop(entries);
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct EncodedAuthorityKey {
    kind: String,
    key_id: String,
    key: String,
}

#[derive(Deserialize)]
struct EncodedAuthorityKeyring {
    keys: Vec<EncodedAuthorityPublicKey>,
}

#[derive(Deserialize)]
struct EncodedAuthorityPublicKey {
    #[serde(alias = "keyId", alias = "key_id")]
    key_id: String,
    #[serde(alias = "publicKey", alias = "key")]
    public_key: String,
}

pub struct AuthorityKeyring {
    keys: HashMap<String, VerifyingKey>,
}

impl AuthorityKeyring {
    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

pub fn generate_authority() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn authority_key_id(key: &VerifyingKey) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(key.as_bytes());
    format!("dev-{}", &encoded[..12])
}

pub fn save_authority_private(path: &Path, key: &SigningKey) -> Result<(), CryptoError> {
    let encoded = EncodedAuthorityKey {
        kind: "ed25519-private".to_owned(),
        key_id: authority_key_id(&key.verifying_key()),
        key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
    };
    write_secret(
        path,
        &serde_json::to_vec_pretty(&encoded).map_err(invalid_key)?,
    )
}

pub fn save_authority_public(path: &Path, key: &VerifyingKey) -> Result<(), CryptoError> {
    let encoded = EncodedAuthorityKey {
        kind: "ed25519-public".to_owned(),
        key_id: authority_key_id(key),
        key: URL_SAFE_NO_PAD.encode(key.as_bytes()),
    };
    write_public(
        path,
        &serde_json::to_vec_pretty(&encoded).map_err(invalid_key)?,
    )
}

pub fn load_authority_private(path: &Path) -> Result<SigningKey, CryptoError> {
    enforce_secret_permissions(path)?;
    let encoded: EncodedAuthorityKey =
        serde_json::from_slice(&fs::read(path)?).map_err(invalid_key)?;
    if encoded.kind != "ed25519-private" {
        return Err(CryptoError::InvalidKey(
            "expected an Ed25519 private key".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded.key).map_err(invalid_key)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("private key must be 32 bytes".to_owned()))?;
    Ok(SigningKey::from_bytes(&array))
}

pub fn load_authority_public(path: &Path) -> Result<(String, VerifyingKey), CryptoError> {
    let encoded: EncodedAuthorityKey =
        serde_json::from_slice(&fs::read(path)?).map_err(invalid_key)?;
    if encoded.kind != "ed25519-public" {
        return Err(CryptoError::InvalidKey(
            "expected an Ed25519 public key".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded.key).map_err(invalid_key)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("public key must be 32 bytes".to_owned()))?;
    let key = VerifyingKey::from_bytes(&array).map_err(invalid_key)?;
    Ok((encoded.key_id, key))
}

pub fn load_authority_keyring(path: &Path) -> Result<AuthorityKeyring, CryptoError> {
    parse_authority_keyring(&fs::read(path)?)
}

fn parse_authority_keyring(data: &[u8]) -> Result<AuthorityKeyring, CryptoError> {
    if let Ok(legacy) = serde_json::from_slice::<EncodedAuthorityKey>(data) {
        if legacy.kind != "ed25519-public" {
            return Err(CryptoError::InvalidKey(
                "expected an Ed25519 public key".to_owned(),
            ));
        }
        let key = decode_verifying_key(&legacy.key)?;
        if authority_key_id(&key) != legacy.key_id {
            return Err(CryptoError::InvalidKey(format!(
                "authority key id {} does not match its public key",
                legacy.key_id
            )));
        }
        let mut keys = HashMap::new();
        keys.insert(legacy.key_id, key);
        return Ok(AuthorityKeyring { keys });
    }
    let encoded: EncodedAuthorityKeyring = serde_json::from_slice(data).map_err(invalid_key)?;
    let mut keys = HashMap::new();
    for entry in encoded.keys {
        let key = decode_verifying_key(&entry.public_key)?;
        if authority_key_id(&key) != entry.key_id {
            return Err(CryptoError::InvalidKey(format!(
                "authority key id {} does not match its public key",
                entry.key_id
            )));
        }
        if keys.insert(entry.key_id.clone(), key).is_some() {
            return Err(CryptoError::InvalidKey(format!(
                "duplicate authority key id {}",
                entry.key_id
            )));
        }
    }
    if keys.is_empty() {
        return Err(CryptoError::InvalidKey(
            "authority keyring must contain at least one key".to_owned(),
        ));
    }
    Ok(AuthorityKeyring { keys })
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(invalid_key)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("public key must be 32 bytes".to_owned()))?;
    VerifyingKey::from_bytes(&array).map_err(invalid_key)
}

pub fn generate_identity() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

pub fn save_identity(path: &Path, key: &identity::Keypair) -> Result<(), CryptoError> {
    let encoded = key
        .to_protobuf_encoding()
        .map_err(|error| CryptoError::InvalidKey(error.to_string()))?;
    write_secret(path, &encoded)
}

pub fn load_identity(path: &Path) -> Result<identity::Keypair, CryptoError> {
    enforce_secret_permissions(path)?;
    identity::Keypair::from_protobuf_encoding(&fs::read(path)?)
        .map_err(|error| CryptoError::InvalidKey(error.to_string()))
}

pub fn load_or_generate_identity(path: &Path) -> Result<identity::Keypair, CryptoError> {
    if path.exists() {
        load_identity(path)
    } else {
        let key = generate_identity();
        save_identity(path, &key)?;
        Ok(key)
    }
}

pub fn sign_identity_payload(
    key: &identity::Keypair,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    key.sign(payload)
        .map_err(|error| CryptoError::InvalidKey(error.to_string()))
}

pub fn issue_ticket(signing_key: &SigningKey, request: &TicketRequest) -> SignedTicket {
    let mut nonce = vec![0_u8; NONCE_BYTES];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    let expires = request
        .now_epoch_seconds
        .saturating_add(i64::try_from(request.ttl_seconds).unwrap_or(i64::MAX));
    let claims = TicketClaims {
        version: PROTOCOL_VERSION,
        connector_peer_id: request.connector_peer_id.to_bytes(),
        agent_peer_id: request.agent_peer_id.to_bytes(),
        target_ip: request.target_ip.to_string(),
        target_port: u32::from(request.target_port),
        issued_at_epoch_seconds: request.now_epoch_seconds,
        not_before_epoch_seconds: request.now_epoch_seconds,
        expires_at_epoch_seconds: expires,
        nonce,
        max_streams: 1,
    };
    let claims_bytes = claims.encode_to_vec();
    let signature = signing_key.sign(&claims_bytes).to_bytes().to_vec();
    SignedTicket {
        claims_bytes,
        key_id: authority_key_id(&signing_key.verifying_key()),
        signature,
    }
}

pub fn verify_ticket(
    ticket: &SignedTicket,
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
    context: &VerificationContext,
    replay_cache: &NonceReplayCache,
) -> Result<TicketClaims, CryptoError> {
    if ticket.key_id != expected_key_id {
        return Err(CryptoError::InvalidTicket(
            "unknown signing key id".to_owned(),
        ));
    }
    let signature =
        Signature::from_slice(&ticket.signature).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(&ticket.claims_bytes, &signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let claims = TicketClaims::decode(ticket.claims_bytes.as_slice())
        .map_err(|error| CryptoError::InvalidTicket(error.to_string()))?;
    validate_claims(&claims, context)?;
    replay_cache.check_and_record(&claims, context.now_epoch_seconds)?;
    Ok(claims)
}

pub fn verify_ticket_with_keyring(
    ticket: &SignedTicket,
    keyring: &AuthorityKeyring,
    context: &VerificationContext,
    replay_cache: &NonceReplayCache,
) -> Result<TicketClaims, CryptoError> {
    let verifying_key = keyring
        .get(&ticket.key_id)
        .ok_or_else(|| CryptoError::InvalidTicket("unknown signing key id".to_owned()))?;
    verify_ticket(ticket, &ticket.key_id, verifying_key, context, replay_cache)
}

fn validate_claims(
    claims: &TicketClaims,
    context: &VerificationContext,
) -> Result<(), CryptoError> {
    if claims.version != PROTOCOL_VERSION {
        return Err(CryptoError::InvalidTicket(
            "unsupported protocol version".to_owned(),
        ));
    }
    if claims.max_streams != 1 || claims.nonce.len() != NONCE_BYTES {
        return Err(CryptoError::InvalidTicket(
            "invalid stream count or nonce".to_owned(),
        ));
    }
    if claims.not_before_epoch_seconds > context.now_epoch_seconds {
        return Err(CryptoError::NotYetValid);
    }
    if claims.expires_at_epoch_seconds < context.now_epoch_seconds {
        return Err(CryptoError::Expired);
    }
    if claims.issued_at_epoch_seconds > claims.not_before_epoch_seconds
        || claims.not_before_epoch_seconds > claims.expires_at_epoch_seconds
    {
        return Err(CryptoError::InvalidTicket(
            "invalid ticket time range".to_owned(),
        ));
    }
    if claims.connector_peer_id != context.connector_peer_id.to_bytes() {
        return Err(CryptoError::WrongConnector);
    }
    if claims.agent_peer_id != context.agent_peer_id.to_bytes() {
        return Err(CryptoError::WrongAgent);
    }
    let claim_ip: IpAddr = claims
        .target_ip
        .parse()
        .map_err(|_| CryptoError::InvalidTicket("target is not an IP address".to_owned()))?;
    if claim_ip != context.target_ip || claims.target_port != u32::from(context.target_port) {
        return Err(CryptoError::WrongTarget(
            context.target_ip,
            context.target_port,
        ));
    }
    Ok(())
}

fn invalid_key(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::InvalidKey(error.to_string())
}

fn enforce_secret_permissions(path: &Path) -> Result<(), CryptoError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(CryptoError::InsecurePermissions(format!(
                "{} has mode {mode:04o}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn write_secret(path: &Path, data: &[u8]) -> Result<(), CryptoError> {
    write_file(path, data, true)
}

fn write_public(path: &Path, data: &[u8]) -> Result<(), CryptoError> {
    write_file(path, data, false)
}

fn write_file(path: &Path, data: &[u8], secret: bool) -> Result<(), CryptoError> {
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
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(request: &TicketRequest, now: i64) -> VerificationContext {
        VerificationContext {
            connector_peer_id: request.connector_peer_id,
            agent_peer_id: request.agent_peer_id,
            target_ip: request.target_ip,
            target_port: request.target_port,
            now_epoch_seconds: now,
        }
    }

    #[test]
    fn validates_and_rejects_replay() {
        let authority = generate_authority();
        let request = TicketRequest {
            connector_peer_id: PeerId::random(),
            agent_peer_id: PeerId::random(),
            target_ip: "127.0.0.1".parse().unwrap(),
            target_port: 22,
            now_epoch_seconds: 1_000,
            ttl_seconds: 300,
        };
        let ticket = issue_ticket(&authority, &request);
        let cache = NonceReplayCache::default();
        verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &context(&request, 1_001),
            &cache,
        )
        .unwrap();
        let replay = verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &context(&request, 1_001),
            &cache,
        )
        .unwrap_err();
        assert!(matches!(replay, CryptoError::Replay));
    }

    #[test]
    fn rejects_expired_wrong_target_and_tampered_tickets() {
        let authority = generate_authority();
        let request = TicketRequest {
            connector_peer_id: PeerId::random(),
            agent_peer_id: PeerId::random(),
            target_ip: "127.0.0.1".parse().unwrap(),
            target_port: 22,
            now_epoch_seconds: 1_000,
            ttl_seconds: 10,
        };
        let ticket = issue_ticket(&authority, &request);
        let expired = verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &context(&request, 1_011),
            &NonceReplayCache::default(),
        )
        .unwrap_err();
        assert!(matches!(expired, CryptoError::Expired));

        let mut wrong = context(&request, 1_001);
        wrong.target_port = 23;
        let wrong_target = verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &wrong,
            &NonceReplayCache::default(),
        )
        .unwrap_err();
        assert!(matches!(wrong_target, CryptoError::WrongTarget(_, 23)));

        let mut tampered = ticket;
        tampered.claims_bytes[0] ^= 1;
        let invalid = verify_ticket(
            &tampered,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &context(&request, 1_001),
            &NonceReplayCache::default(),
        )
        .unwrap_err();
        assert!(matches!(invalid, CryptoError::InvalidSignature));
    }

    #[test]
    fn rejects_future_and_wrong_peer() {
        let authority = generate_authority();
        let request = TicketRequest {
            connector_peer_id: PeerId::random(),
            agent_peer_id: PeerId::random(),
            target_ip: "::1".parse().unwrap(),
            target_port: 443,
            now_epoch_seconds: 2_000,
            ttl_seconds: 300,
        };
        let ticket = issue_ticket(&authority, &request);
        let future = verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &context(&request, 1_999),
            &NonceReplayCache::default(),
        )
        .unwrap_err();
        assert!(matches!(future, CryptoError::NotYetValid));

        let mut wrong_peer = context(&request, 2_001);
        wrong_peer.connector_peer_id = PeerId::random();
        let wrong = verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &wrong_peer,
            &NonceReplayCache::default(),
        )
        .unwrap_err();
        assert!(matches!(wrong, CryptoError::WrongConnector));

        let mut wrong_agent = context(&request, 2_001);
        wrong_agent.agent_peer_id = PeerId::random();
        let wrong = verify_ticket(
            &ticket,
            &authority_key_id(&authority.verifying_key()),
            &authority.verifying_key(),
            &wrong_agent,
            &NonceReplayCache::default(),
        )
        .unwrap_err();
        assert!(matches!(wrong, CryptoError::WrongAgent));
    }

    #[test]
    fn verifies_tickets_with_rotating_authority_keyring() {
        let active = generate_authority();
        let previous = generate_authority();
        let mut keys = HashMap::new();
        keys.insert(
            authority_key_id(&active.verifying_key()),
            active.verifying_key(),
        );
        keys.insert(
            authority_key_id(&previous.verifying_key()),
            previous.verifying_key(),
        );
        let keyring = AuthorityKeyring { keys };
        let request = TicketRequest {
            connector_peer_id: PeerId::random(),
            agent_peer_id: PeerId::random(),
            target_ip: "127.0.0.1".parse().unwrap(),
            target_port: 22,
            now_epoch_seconds: 3_000,
            ttl_seconds: 300,
        };
        let ticket = issue_ticket(&previous, &request);
        verify_ticket_with_keyring(
            &ticket,
            &keyring,
            &context(&request, 3_001),
            &NonceReplayCache::default(),
        )
        .unwrap();
    }

    #[test]
    fn parses_website_authority_keyring_response() {
        let active = generate_authority().verifying_key();
        let previous = generate_authority().verifying_key();
        let active_id = authority_key_id(&active);
        let previous_id = authority_key_id(&previous);
        let document = serde_json::json!({
            "algorithm": "Ed25519",
            "keyId": active_id,
            "publicKey": URL_SAFE_NO_PAD.encode(active.as_bytes()),
            "protocolVersion": 1,
            "keys": [
                {
                    "keyId": active_id,
                    "publicKey": URL_SAFE_NO_PAD.encode(active.as_bytes()),
                    "active": true
                },
                {
                    "keyId": previous_id,
                    "publicKey": URL_SAFE_NO_PAD.encode(previous.as_bytes()),
                    "active": false
                }
            ]
        });

        let keyring = parse_authority_keyring(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(keyring.len(), 2);
        assert_eq!(keyring.get(&active_id), Some(&active));
        assert_eq!(keyring.get(&previous_id), Some(&previous));
    }

    #[test]
    fn signs_control_plane_challenge_with_libp2p_identity() {
        let identity = generate_identity();
        let payload = b"jlshell-link-node-proof/v1";
        let signature = sign_identity_payload(&identity, payload).unwrap();
        let public = identity.public().try_into_ed25519().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public.to_bytes()).unwrap();
        verifying_key
            .verify(payload, &Signature::from_slice(&signature).unwrap())
            .unwrap();
    }
}
