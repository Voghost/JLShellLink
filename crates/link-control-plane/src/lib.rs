use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderValue};

const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct ControlPlaneClient {
    base_url: String,
    client: reqwest::Client,
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

    /// Sends a Relay heartbeat using the short-lived node credential.
    pub async fn relay_heartbeat(&self, credential: &str, version: &str) -> Result<()> {
        self.heartbeat(
            "/api/v1/link/relay-heartbeats",
            "X-Relay-Token",
            credential,
            version,
        )
        .await
    }

    async fn heartbeat(
        &self,
        path: &str,
        header: &'static str,
        credential: &str,
        version: &str,
    ) -> Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header,
            HeaderValue::from_str(credential.trim()).context("invalid node credential")?,
        );
        self.post(path, headers, &serde_json::json!({ "version": version }))
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
        if !response.status().is_success() {
            bail!(
                "control-plane heartbeat returned HTTP {}",
                response.status()
            );
        }
        Ok(())
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(self.url(path))
            .send()
            .await
            .context("control-plane request failed")?;
        if !response.status().is_success() {
            bail!("control-plane request returned HTTP {}", response.status());
        }
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
}
