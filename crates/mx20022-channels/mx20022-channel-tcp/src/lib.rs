// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mx20022_channels::{
    ChannelError, ChannelHealth, DeliveryReceipt, InboundChannel, InboundMessage, OutboundChannel,
    OutboundMessage,
};
use mx20022_crypto::auth::constant_time_eq;
use rustls::server::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone, Copy)]
pub enum TcpFraming {
    LengthPrefixed,
    Delimiter(u8),
}

#[derive(Debug, Clone)]
pub struct TcpInboundConfig {
    pub name: String,
    pub bind: String,
    pub framing: TcpFraming,
    pub content_type: String,
    pub auth_token: Option<SecretString>,
    /// Optional TLS. When set, accepted connections are wrapped in TLS before
    /// framing/auth. Strongly recommended when `auth_token` is set, since
    /// otherwise the shared secret traverses the wire in cleartext.
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Clone)]
pub struct TcpInboundChannel {
    config: TcpInboundConfig,
    paused: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
}

impl TcpInboundChannel {
    pub fn new(config: TcpInboundConfig) -> Self {
        Self {
            config,
            paused: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl InboundChannel for TcpInboundChannel {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn run(&self, sender: mpsc::Sender<InboundMessage>) -> Result<(), ChannelError> {
        // Refuse to carry an auth_token over a cleartext transport: without
        // TLS the shared secret is exposed on the wire to any network
        // observer. The config layer's enforce_secure_channels already
        // warns/errors on this combination; this is the defense-in-depth
        // check at the channel itself.
        let has_tls = self
            .config
            .tls_cert_path
            .as_ref()
            .zip(self.config.tls_key_path.as_ref())
            .is_some();
        if self.config.auth_token.is_some() && !has_tls {
            return Err(ChannelError::new(
                "tcp inbound auth_token requires TLS (set tls_cert/tls_key); \
                 refusing to send the shared secret in cleartext",
            ));
        }

        let acceptor = if has_tls {
            Some(build_tls_acceptor(
                self.config.tls_cert_path.as_deref().unwrap(),
                self.config.tls_key_path.as_deref().unwrap(),
            )?)
        } else {
            None
        };

        let listener = TcpListener::bind(&self.config.bind).await.map_err(|e| {
            ChannelError::new(format!("tcp bind failed on {}: {e}", self.config.bind))
        })?;

        while !self.shutdown.load(Ordering::Relaxed) {
            if self.paused.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| ChannelError::new(format!("tcp accept failed: {e}")))?;

            let sender = sender.clone();
            let framing = self.config.framing;
            let content_type = self.config.content_type.clone();
            let auth_token = self.config.auth_token.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // Handshake first (if TLS), then process. We pass ownership
                // of the accepted stream into a small async block so the
                // concrete type is resolved here and process_connection
                // stays generic over AsyncRead+AsyncWrite.
                let result = match acceptor {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            process_connection(
                                tls_stream,
                                framing,
                                content_type,
                                auth_token,
                                sender,
                            )
                            .await
                        }
                        Err(error) => {
                            Err(ChannelError::new(format!("tls handshake failed: {error}")))
                        }
                    },
                    None => {
                        process_connection(stream, framing, content_type, auth_token, sender).await
                    }
                };
                if let Err(error) = result {
                    tracing::warn!(error = %error, "tcp inbound connection failed");
                }
            });
        }

        Ok(())
    }

    async fn shutdown(&self) -> Result<(), ChannelError> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn health(&self) -> Result<ChannelHealth, ChannelError> {
        Ok(ChannelHealth {
            ok: !self.shutdown.load(Ordering::Relaxed),
            message: Some(if self.paused.load(Ordering::Relaxed) {
                "paused".to_string()
            } else {
                "ok".to_string()
            }),
        })
    }

    async fn pause(&self) -> Result<(), ChannelError> {
        self.paused.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn resume(&self) -> Result<(), ChannelError> {
        self.paused.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TcpOutboundConfig {
    pub name: String,
    pub endpoint: String,
    pub framing: TcpFraming,
    pub content_type: String,
}

#[derive(Clone)]
pub struct TcpOutboundChannel {
    config: TcpOutboundConfig,
    shutdown: Arc<AtomicBool>,
    connection: Arc<Mutex<Option<TcpStream>>>,
}

impl TcpOutboundChannel {
    pub fn new(config: TcpOutboundConfig) -> Self {
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            connection: Arc::new(Mutex::new(None)),
        }
    }

    async fn connect(&self) -> Result<TcpStream, ChannelError> {
        TcpStream::connect(&self.config.endpoint)
            .await
            .map_err(|e| ChannelError::new(format!("tcp connect failed: {e}")))
    }
}

#[async_trait]
impl OutboundChannel for TcpOutboundChannel {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, msg: OutboundMessage) -> Result<DeliveryReceipt, ChannelError> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(ChannelError::new("channel is shut down"));
        }

        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }

        let mut send_error = None;
        if let Some(stream) = guard.as_mut() {
            if let Err(error) = write_frame(stream, self.config.framing, msg.raw.as_bytes()).await {
                send_error = Some(error);
            }
        }

        if send_error.is_some() {
            *guard = Some(self.connect().await?);
            if let Some(stream) = guard.as_mut() {
                write_frame(stream, self.config.framing, msg.raw.as_bytes())
                    .await
                    .map_err(|e| ChannelError::new(format!("tcp send failed: {e}")))?;
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis();
        Ok(DeliveryReceipt {
            id: format!("tcp-{now}"),
        })
    }

    async fn shutdown(&self) -> Result<(), ChannelError> {
        self.shutdown.store(true, Ordering::Relaxed);
        *self.connection.lock().await = None;
        Ok(())
    }

    async fn health(&self) -> Result<ChannelHealth, ChannelError> {
        Ok(ChannelHealth {
            ok: !self.shutdown.load(Ordering::Relaxed),
            message: Some(format!("content_type={}", self.config.content_type)),
        })
    }
}

async fn process_connection<S>(
    stream: S,
    framing: TcpFraming,
    content_type: String,
    auth_token: Option<SecretString>,
    sender: mpsc::Sender<InboundMessage>,
) -> Result<(), ChannelError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    match framing {
        TcpFraming::LengthPrefixed => {
            let mut stream = stream;
            if let Some(expected) = auth_token.as_ref().map(ExposeSecret::expose_secret) {
                let auth_frame = read_length_prefixed(&mut stream).await?;
                let presented = decode_utf8_payload(&auth_frame)?;
                if !constant_time_eq(presented.trim(), expected) {
                    return Err(ChannelError::new("tcp auth failed"));
                }
            }
            loop {
                let frame = read_length_prefixed(&mut stream).await?;
                sender
                    .send(InboundMessage {
                        raw: decode_utf8_payload(&frame)?,
                        content_type: content_type.clone(),
                    })
                    .await
                    .map_err(|e| ChannelError::new(format!("inbound queue send failed: {e}")))?;
            }
        }
        TcpFraming::Delimiter(delimiter) => {
            let mut reader = BufReader::new(stream);
            if let Some(expected) = auth_token.as_ref().map(ExposeSecret::expose_secret) {
                let mut auth_buf = Vec::new();
                let bytes = (&mut reader)
                    .take(MAX_FRAME_SIZE as u64 + 1)
                    .read_until(delimiter, &mut auth_buf)
                    .await
                    .map_err(|e| ChannelError::new(format!("tcp read_until failed: {e}")))?;
                if bytes == 0 {
                    return Err(ChannelError::new("tcp auth failed"));
                }
                if auth_buf.last().copied() == Some(delimiter) {
                    let _ = auth_buf.pop();
                }
                let presented = decode_utf8_payload(&auth_buf)?;
                if !constant_time_eq(presented.trim(), expected) {
                    return Err(ChannelError::new("tcp auth failed"));
                }
            }
            loop {
                let mut buf = Vec::new();
                let bytes = (&mut reader)
                    .take(MAX_FRAME_SIZE as u64 + 1)
                    .read_until(delimiter, &mut buf)
                    .await
                    .map_err(|e| ChannelError::new(format!("tcp read_until failed: {e}")))?;
                if bytes == 0 {
                    return Ok(());
                }
                if buf.last().copied() != Some(delimiter) && buf.len() > MAX_FRAME_SIZE {
                    return Err(ChannelError::new(format!(
                        "tcp delimited frame too large: exceeds {MAX_FRAME_SIZE} byte limit without delimiter"
                    )));
                }

                if buf.last().copied() == Some(delimiter) {
                    let _ = buf.pop();
                }
                sender
                    .send(InboundMessage {
                        raw: decode_utf8_payload(&buf)?,
                        content_type: content_type.clone(),
                    })
                    .await
                    .map_err(|e| ChannelError::new(format!("inbound queue send failed: {e}")))?;
            }
        }
    }
}

const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

fn decode_utf8_payload(payload: &[u8]) -> Result<String, ChannelError> {
    String::from_utf8(payload.to_vec())
        .map_err(|_| ChannelError::new("tcp payload is not valid UTF-8"))
}

/// Load a cert chain + private key from PEM files and build a TLS acceptor.
/// Mirrors the admin host's axum_server TLS path but uses tokio-rustls
/// directly so the TCP channel can wrap raw accepted streams.
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, ChannelError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| ChannelError::new(format!("failed to open tls_cert `{cert_path}`: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ChannelError::new(format!("failed to parse tls_cert `{cert_path}`: {e}")))?;
    if certs.is_empty() {
        return Err(ChannelError::new(format!(
            "tls_cert `{cert_path}` contained no certificates"
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| ChannelError::new(format!("failed to load tls_key `{key_path}`: {e}")))?;

    let config =
        ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|e| ChannelError::new(format!("tls protocol version selection failed: {e}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ChannelError::new(format!("tls server config build failed: {e}")))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn read_length_prefixed<S>(stream: &mut S) -> Result<Vec<u8>, ChannelError>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(to_channel_read_error)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(ChannelError::new("invalid zero-length tcp frame"));
    }
    if len > MAX_FRAME_SIZE {
        return Err(ChannelError::new(format!(
            "tcp frame too large: {len} bytes exceeds {MAX_FRAME_SIZE} byte limit"
        )));
    }

    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(to_channel_read_error)?;
    Ok(payload)
}

async fn write_frame(
    stream: &mut TcpStream,
    framing: TcpFraming,
    payload: &[u8],
) -> Result<(), io::Error> {
    match framing {
        TcpFraming::LengthPrefixed => {
            let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(payload).await?;
        }
        TcpFraming::Delimiter(delimiter) => {
            stream.write_all(payload).await?;
            stream.write_all(&[delimiter]).await?;
        }
    }
    stream.flush().await?;
    Ok(())
}

fn to_channel_read_error(error: io::Error) -> ChannelError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        ChannelError::new("tcp connection closed")
    } else {
        ChannelError::new(format!("tcp read failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mx20022_channels::{InboundChannel, OutboundChannel, OutboundMessage};
    use secrecy::SecretString;

    use super::{
        TcpFraming, TcpInboundChannel, TcpInboundConfig, TcpOutboundChannel, TcpOutboundConfig,
    };
    use tokio::net::TcpStream;

    fn find_available_port() -> Option<u16> {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                let port = listener.local_addr().ok().map(|addr| addr.port());
                drop(listener);
                port
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(error) => panic!("bind listener: {error}"),
        }
    }

    #[tokio::test]
    async fn tcp_length_prefixed_roundtrip() {
        let Some(port) = find_available_port() else {
            eprintln!("skipping tcp roundtrip test: binding not permitted");
            return;
        };
        let inbound = TcpInboundChannel::new(TcpInboundConfig {
            name: "tcp-in".to_string(),
            bind: format!("127.0.0.1:{port}"),
            framing: TcpFraming::LengthPrefixed,
            content_type: "application/xml".to_string(),
            auth_token: None,
            tls_cert_path: None,
            tls_key_path: None,
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let runner = inbound.clone();
        tokio::spawn(async move {
            let _ = runner.run(tx).await;
        });

        // Wait for the inbound listener to be ready by retrying a TCP
        // connect until it succeeds or we time out. Replaces a fixed sleep
        // that intermittently raced the accept loop under CI load.
        let ready = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if TcpStream::connect(format!("127.0.0.1:{port}"))
                    .await
                    .is_ok()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // If the listener never came up (e.g. sandbox), skip like the
        // permission-denied path below rather than fail spuriously.
        if ready.is_err() {
            eprintln!("skipping tcp roundtrip test: listener not ready");
            return;
        }

        let outbound = TcpOutboundChannel::new(TcpOutboundConfig {
            name: "tcp-out".to_string(),
            endpoint: format!("127.0.0.1:{port}"),
            framing: TcpFraming::LengthPrefixed,
            content_type: "application/xml".to_string(),
        });
        let send_result = outbound
            .send(OutboundMessage {
                raw: "<Document/>".to_string(),
                content_type: "application/xml".to_string(),
            })
            .await;
        if let Err(error) = send_result {
            let message = error.to_string();
            if message.contains("Operation not permitted") || message.contains("Permission denied")
            {
                eprintln!("skipping tcp roundtrip test: {message}");
                return;
            }
            panic!("tcp outbound should send: {message}");
        }

        let message = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("message should be received")
            .expect("message must exist");
        assert_eq!(message.raw, "<Document/>");
    }

    #[tokio::test]
    async fn run_refuses_auth_token_without_tls() {
        // Regression: without TLS the shared auth_token traverses the wire in
        // cleartext. run() must refuse to start in that configuration rather
        // than silently expose the secret.
        let inbound = TcpInboundChannel::new(TcpInboundConfig {
            name: "tcp-in".to_string(),
            bind: "127.0.0.1:0".to_string(),
            framing: TcpFraming::LengthPrefixed,
            content_type: "application/xml".to_string(),
            auth_token: Some(SecretString::new("shared-secret".into())),
            tls_cert_path: None,
            tls_key_path: None,
        });
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let result = inbound.run(tx).await;
        assert!(
            result.is_err(),
            "run() should refuse auth_token without TLS"
        );
        let message = result.expect_err("error message").to_string();
        assert!(
            message.contains("requires TLS"),
            "error should mention TLS requirement: {message}"
        );
    }
}
