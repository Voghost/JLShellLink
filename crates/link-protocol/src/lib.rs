use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use prost::Message;
use thiserror::Error;

pub const TCP_PROTOCOL: &str = "/jlshell/link/tcp/1.0.0";
pub const RELAY_AUTH_PROTOCOL: &str = "/jlshell/link/relay-auth/1.0.0";
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_CONTROL_FRAME_SIZE: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, Message)]
pub struct TicketClaims {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub connector_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub agent_peer_id: Vec<u8>,
    #[prost(string, tag = "4")]
    pub target_ip: String,
    #[prost(uint32, tag = "5")]
    pub target_port: u32,
    #[prost(int64, tag = "6")]
    pub issued_at_epoch_seconds: i64,
    #[prost(int64, tag = "7")]
    pub not_before_epoch_seconds: i64,
    #[prost(int64, tag = "8")]
    pub expires_at_epoch_seconds: i64,
    #[prost(bytes = "vec", tag = "9")]
    pub nonce: Vec<u8>,
    #[prost(uint32, tag = "10")]
    pub max_streams: u32,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct SignedTicket {
    #[prost(bytes = "vec", tag = "1")]
    pub claims_bytes: Vec<u8>,
    #[prost(string, tag = "2")]
    pub key_id: String,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct OpenTcpRequest {
    #[prost(message, optional, tag = "1")]
    pub ticket: Option<SignedTicket>,
    #[prost(string, tag = "2")]
    pub target_ip: String,
    #[prost(uint32, tag = "3")]
    pub target_port: u32,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct OpenTcpResponse {
    #[prost(enumeration = "OpenStatus", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum OpenStatus {
    Unspecified = 0,
    Ok = 1,
    Unauthorized = 2,
    TargetDenied = 3,
    ConnectFailed = 4,
    BadRequest = 5,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct RelayAuthRequest {
    #[prost(string, tag = "1")]
    pub grant_credential: String,
    #[prost(bytes = "vec", tag = "2")]
    pub agent_peer_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct RelayAuthResponse {
    #[prost(enumeration = "RelayAuthStatus", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(string, tag = "3")]
    pub grant_id: String,
    #[prost(uint64, tag = "4")]
    pub remaining_bytes: u64,
    #[prost(int64, tag = "5")]
    pub expires_at_epoch_seconds: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum RelayAuthStatus {
    Unspecified = 0,
    Ok = 1,
    Unauthorized = 2,
    TargetDenied = 3,
    Exhausted = 4,
    BadRequest = 5,
    ControlPlaneUnavailable = 6,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("control frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("invalid protobuf frame: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("failed to encode protobuf frame: {0}")]
    Encode(#[from] prost::EncodeError),
}

/// Writes one bounded, length-prefixed Protobuf control frame.
///
/// # Errors
///
/// Returns an error when encoding fails, the frame exceeds the limit, or the stream cannot write.
pub async fn write_frame<W, M>(writer: &mut W, message: &M) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let mut payload = Vec::with_capacity(message.encoded_len());
    message.encode(&mut payload)?;
    if payload.len() > MAX_CONTROL_FRAME_SIZE {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads and decodes one bounded, length-prefixed Protobuf control frame.
///
/// # Errors
///
/// Returns an error for I/O failure, an oversized frame, or invalid Protobuf bytes.
pub async fn read_frame<R, M>(reader: &mut R) -> Result<M, FrameError>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_CONTROL_FRAME_SIZE {
        return Err(FrameError::TooLarge(length));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(M::decode(payload.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[tokio::test]
    async fn round_trips_control_frame() {
        let request = OpenTcpRequest {
            ticket: None,
            target_ip: "127.0.0.1".to_owned(),
            target_port: 22,
        };
        let mut bytes = Cursor::new(Vec::new());
        write_frame(&mut bytes, &request).await.unwrap();
        bytes.set_position(0);
        let decoded: OpenTcpRequest = read_frame(&mut bytes).await.unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn round_trips_relay_auth_frame() {
        let request = RelayAuthRequest {
            grant_credential: "opaque-grant".to_owned(),
            agent_peer_id: vec![1, 2, 3],
        };
        let mut bytes = Cursor::new(Vec::new());
        write_frame(&mut bytes, &request).await.unwrap();
        bytes.set_position(0);
        let decoded: RelayAuthRequest = read_frame(&mut bytes).await.unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocation() {
        let oversized = u32::try_from(MAX_CONTROL_FRAME_SIZE + 1).unwrap();
        let mut bytes = Cursor::new(oversized.to_be_bytes().to_vec());
        let error = read_frame::<_, OpenTcpRequest>(&mut bytes)
            .await
            .unwrap_err();
        assert!(matches!(error, FrameError::TooLarge(_)));
    }

    #[test]
    fn java_control_plane_claims_fixture_is_wire_compatible() {
        let mut connector_peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        connector_peer_id.extend([0x11; 32]);
        let mut agent_peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        agent_peer_id.extend([0x22; 32]);
        let claims = TicketClaims {
            version: 1,
            connector_peer_id,
            agent_peer_id,
            target_ip: "127.0.0.1".to_owned(),
            target_port: 22,
            issued_at_epoch_seconds: 1_000,
            not_before_epoch_seconds: 1_000,
            expires_at_epoch_seconds: 1_300,
            nonce: vec![0x33; 32],
            max_streams: 1,
        };
        let expected = decode_hex(concat!(
            "08011226002408011220",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1a26002408011220",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "22093132372e302e302e31",
            "281630e80738e80740940a4a20",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "5001"
        ));
        assert_eq!(claims.encode_to_vec(), expected);
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }
}
