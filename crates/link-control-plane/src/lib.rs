use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_ERROR_RESPONSE_BYTES: u64 = 4 * 1024;

#[derive(Clone)]
pub struct ControlPlaneClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedRelayGrant {
    pub grant_id: String,
    pub user_id: String,
    pub relay_id: String,
    pub agent_id: String,
    pub agent_peer_id: String,
    pub byte_limit: u64,
    pub used_bytes: u64,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedRelayAgent {
    pub agent_id: String,
    pub user_id: String,
    pub agent_peer_id: String,
    pub credential_expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RelayUsageReport<'a> {
    pub grant_id: &'a str,
    pub sequence: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub closed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RelayUsageResult {
    pub grant_id: String,
    pub sequence: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub remaining_bytes: u64,
    pub closed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnrolledAgent {
    pub credential: String,
}

impl ControlPlaneClient {
    /// Creates a control-plane client. Plain HTTP is accepted only for an explicit loopback URL.
    pub fn new(base_url: &str) -> Result<Self> {
        let parsed = reqwest::Url::parse(base_url).context("invalid control-plane URL")?;
        let secure = parsed.scheme() == "https";
        let loopback = parsed.scheme() == "http"
            && parsed
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
        if !secure && !loopback {
            bail!("control-plane URL must use HTTPS (HTTP is allowed only on loopback)");
        }
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            bail!(
                "control-plane URL must be an origin without credentials, path, query, or fragment"
            );
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("cannot create HTTPS client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
        })
    }

    /// Downloads the current ticket Authority keyring.
    pub async fn authority_keyring(&self) -> Result<Vec<u8>> {
        self.get("/api/v1/link/ticket-authority").await
    }

    /// Sends an Agent heartbeat using the short-lived node credential.
    pub async fn agent_heartbeat(
        &self,
        credential: &str,
        version: &str,
        addresses: &[String],
    ) -> Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Agent-Token",
            HeaderValue::from_str(credential.trim()).context("invalid node credential")?,
        );
        self.post(
            "/api/v1/link/agent-heartbeats",
            headers,
            &serde_json::json!({ "version": version, "addresses": addresses }),
        )
        .await
    }

    /// Consumes a one-time Website enrollment token and returns the long-lived node credential.
    pub async fn consume_agent_enrollment(
        &self,
        enrollment_token: &str,
        platform: &str,
        architecture: &str,
        public_key: &str,
        version: &str,
    ) -> Result<EnrolledAgent> {
        self.post_json(
            "/api/v1/link/agent-enrollments/consume",
            HeaderMap::new(),
            &serde_json::json!({
                "enrollmentToken": enrollment_token.trim(),
                "platform": platform,
                "architecture": architecture,
                "publicKey": public_key,
                "version": version,
            }),
        )
        .await
    }

    /// Sends a Relay heartbeat and optionally synchronizes its public IP multiaddr.
    pub async fn relay_heartbeat(
        &self,
        credential: &str,
        version: &str,
        endpoint: Option<&str>,
    ) -> Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Relay-Token",
            credential_header(credential, "relay credential")?,
        );
        self.post(
            "/api/v1/link/relay-heartbeats",
            headers,
            &serde_json::json!({ "version": version, "endpoint": endpoint }),
        )
        .await
    }

    /// Validates a single-use Relay Grant against the authenticated Relay node.
    pub async fn validate_relay_grant(
        &self,
        relay_credential: &str,
        grant_credential: &str,
    ) -> Result<ValidatedRelayGrant> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Relay-Token",
            credential_header(relay_credential, "relay credential")?,
        );
        headers.insert(
            "X-Relay-Grant",
            credential_header(grant_credential, "relay grant")?,
        );
        self.post_json(
            "/api/v1/link/relay-grant-validations",
            headers,
            &serde_json::Value::Null,
        )
        .await
    }

    /// Validates an Agent node credential for a Relay reservation.
    pub async fn validate_relay_agent(
        &self,
        relay_credential: &str,
        agent_credential: &str,
    ) -> Result<ValidatedRelayAgent> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Relay-Token",
            credential_header(relay_credential, "relay credential")?,
        );
        headers.insert(
            "X-Agent-Token",
            credential_header(agent_credential, "agent credential")?,
        );
        self.post_json(
            "/api/v1/link/relay-agent-validations",
            headers,
            &serde_json::Value::Null,
        )
        .await
    }

    /// Reports monotonic bidirectional byte counters for an active Relay Grant.
    pub async fn report_relay_usage(
        &self,
        relay_credential: &str,
        report: &RelayUsageReport<'_>,
    ) -> Result<RelayUsageResult> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Relay-Token",
            credential_header(relay_credential, "relay credential")?,
        );
        self.post_json("/api/v1/link/relay-usage", headers, report)
            .await
    }

    async fn post(&self, path: &str, headers: HeaderMap, body: &serde_json::Value) -> Result<()> {
        let response = self
            .client
            .post(self.url(path))
            .headers(headers)
            .json(body)
            .send()
            .await
            .context("control-plane heartbeat failed")?;
        ensure_success(response, "control-plane heartbeat").await?;
        Ok(())
    }

    async fn post_json<T: Serialize + Sync + ?Sized, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        headers: HeaderMap,
        body: &T,
    ) -> Result<R> {
        let request = self.client.post(self.url(path)).headers(headers);
        let response = if path.ends_with("validations") {
            request.send().await
        } else {
            request.json(body).send().await
        }
        .context("control-plane request failed")?;
        let response = ensure_success(response, "control-plane request").await?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            bail!("control-plane response is too large");
        }
        let bytes = response
            .bytes()
            .await
            .context("cannot read control-plane response")?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            bail!("control-plane response is too large");
        }
        serde_json::from_slice(&bytes).context("invalid control-plane JSON response")
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(self.url(path))
            .send()
            .await
            .context("control-plane request failed")?;
        let response = ensure_success(response, "control-plane request").await?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            bail!("control-plane response is too large");
        }
        let bytes = response
            .bytes()
            .await
            .context("cannot read control-plane response")?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            bail!("control-plane response is too large");
        }
        Ok(bytes.to_vec())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

async fn ensure_success(response: reqwest::Response, operation: &str) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let detail = if response
        .content_length()
        .is_some_and(|length| length <= MAX_ERROR_RESPONSE_BYTES)
    {
        response
            .text()
            .await
            .ok()
            .filter(|value| !value.trim().is_empty())
    } else {
        None
    };
    if let Some(detail) = detail {
        bail!("{operation} returned HTTP {status}: {detail}");
    }
    bail!("{operation} returned HTTP {status}")
}

fn credential_header(value: &str, name: &str) -> Result<HeaderValue> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        bail!("{name} is invalid");
    }
    HeaderValue::from_str(value).with_context(|| format!("{name} is invalid"))
}

/// Reads a node credential and enforces owner-only permissions on Unix.
pub fn read_node_credential(path: &Path) -> Result<String> {
    enforce_owner_only(path)?;
    let value = fs::read_to_string(path)
        .with_context(|| format!("cannot read node credential {}", path.display()))?;
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        bail!("node credential file is invalid");
    }
    Ok(value.to_owned())
}

/// Atomically writes a node credential and applies owner-only permissions on Unix.
pub fn write_node_credential(path: &Path, credential: &str) -> Result<()> {
    let credential = credential.trim();
    if credential.is_empty()
        || credential.len() > 512
        || credential.chars().any(char::is_whitespace)
    {
        bail!("node credential is invalid");
    }
    let parent = path
        .parent()
        .context("node credential path must have a parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("cannot create {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot secure {}", parent.display()))?;
    }
    let temporary = temporary_credential_path(path);
    fs::write(&temporary, format!("{credential}\n"))
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot secure {}", temporary.display()))?;
    }
    fs::rename(&temporary, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

fn temporary_credential_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("credential");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}

fn enforce_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "node credential file permissions must be 0600: {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plaintext_non_loopback_control_plane() {
        assert!(ControlPlaneClient::new("http://example.com").is_err());
        assert!(ControlPlaneClient::new("http://127.0.0.1:8080").is_ok());
        assert!(ControlPlaneClient::new("https://example.com").is_ok());
        assert!(ControlPlaneClient::new("https://example.com/control").is_err());
        assert!(ControlPlaneClient::new("https://example.com/#fragment").is_err());
    }

    #[test]
    fn decodes_relay_grant_and_usage_contracts() {
        let grant: ValidatedRelayGrant = serde_json::from_str(
            r#"{"grantId":"11111111-1111-1111-1111-111111111111","userId":"22222222-2222-2222-2222-222222222222","relayId":"33333333-3333-3333-3333-333333333333","agentId":"44444444-4444-4444-4444-444444444444","agentPeerId":"12D3KooWAgent","byteLimit":4096,"usedBytes":10,"expiresAt":"2026-08-03T10:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(grant.byte_limit, 4096);
        assert_eq!(grant.agent_peer_id, "12D3KooWAgent");

        let report = RelayUsageReport {
            grant_id: &grant.grant_id,
            sequence: 1,
            uploaded_bytes: 20,
            downloaded_bytes: 30,
            closed: false,
        };
        let encoded = serde_json::to_value(report).unwrap();
        assert_eq!(encoded["uploadedBytes"], 20);
        assert_eq!(encoded["downloadedBytes"], 30);

        let agent: ValidatedRelayAgent = serde_json::from_str(
            r#"{"agentId":"agent-id","userId":"user-id","agentPeerId":"12D3KooWAgent","credentialExpiresAt":"2030-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(agent.agent_peer_id, "12D3KooWAgent");
    }

    #[test]
    fn rejects_invalid_relay_credentials_before_network_use() {
        assert!(credential_header("", "relay credential").is_err());
        assert!(credential_header("contains whitespace", "relay grant").is_err());
        assert!(credential_header("valid-token", "relay grant").is_ok());
    }

    #[test]
    fn writes_owner_only_credentials_that_can_be_read_back() {
        let temporary = std::env::temp_dir().join(format!(
            "jlshell-link-control-plane-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let credential = temporary.join("state").join("agent.token");

        write_node_credential(&credential, "enrolled-agent-token").unwrap();

        assert_eq!(
            read_node_credential(&credential).unwrap(),
            "enrolled-agent-token"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(temporary).unwrap();
    }
}
