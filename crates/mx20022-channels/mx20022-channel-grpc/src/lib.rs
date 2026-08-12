// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use mx20022_channels::auth::{authorize_inbound, InboundAuthConfig, InboundAuthContext};
use mx20022_channels::{
    ChannelError, ChannelHealth, DeliveryReceipt, InboundChannel, InboundMessage, OutboundChannel,
    OutboundMessage,
};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("mx20022.runtime.channel.grpc.v1");
}

#[derive(Clone)]
pub struct GrpcInboundConfig {
    pub name: String,
    pub bind: String,
    pub auth: InboundAuthConfig,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Clone)]
pub struct GrpcInboundChannel {
    config: GrpcInboundConfig,
    paused: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
}

impl GrpcInboundChannel {
    pub fn new(config: GrpcInboundConfig) -> Self {
        Self {
            config,
            paused: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn run_with_listener(
        &self,
        listener: tokio::net::TcpListener,
        sender: mpsc::Sender<InboundMessage>,
    ) -> Result<(), ChannelError> {
        let service = InboundService {
            sender,
            paused: Arc::clone(&self.paused),
            shutdown: Arc::clone(&self.shutdown),
            auth: self.config.auth.clone(),
        };

        let mut builder = Server::builder();
        if let Some(identity) = self.load_inbound_identity()? {
            let tls = ServerTlsConfig::new().identity(identity);
            builder = builder
                .tls_config(tls)
                .map_err(|e| ChannelError::new(format!("grpc inbound tls config failed: {e}")))?;
        } else {
            tracing::warn!(channel = %self.config.name, bind = %self.config.bind, "grpc inbound channel starting without TLS");
        }

        builder
            .add_service(proto::runtime_channel_server::RuntimeChannelServer::new(
                service,
            ))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .map_err(|e| ChannelError::new(format!("grpc inbound server failed: {e}")))
    }
}

#[derive(Clone)]
struct InboundService {
    sender: mpsc::Sender<InboundMessage>,
    paused: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    auth: InboundAuthConfig,
}

#[tonic::async_trait]
impl proto::runtime_channel_server::RuntimeChannel for InboundService {
    async fn send_inbound(
        &self,
        request: Request<proto::InboundEnvelope>,
    ) -> Result<Response<proto::DeliveryAck>, Status> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(Status::unavailable("channel shutting down"));
        }
        if self.paused.load(Ordering::Relaxed) {
            return Err(Status::unavailable("channel paused"));
        }

        authorize_inbound(
            &self.auth,
            InboundAuthContext {
                authorization_header: request
                    .metadata()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                mtls_subject: request
                    .metadata()
                    .get(self.auth.mtls_subject_header.as_str())
                    .and_then(|value| value.to_str().ok()),
            },
        )
        .map_err(|error| {
            if error.to_string().contains("forbidden")
                || error.to_string().contains("untrusted mTLS")
            {
                Status::permission_denied(error.to_string())
            } else {
                Status::unauthenticated(error.to_string())
            }
        })?;

        let envelope = request.into_inner();
        self.sender
            .send(InboundMessage {
                raw: envelope.raw,
                content_type: envelope.content_type,
            })
            .await
            .map_err(|e| Status::internal(format!("failed to enqueue inbound message: {e}")))?;

        Ok(Response::new(proto::DeliveryAck {
            id: "accepted".to_string(),
        }))
    }
}

#[async_trait]
impl InboundChannel for GrpcInboundChannel {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn run(&self, sender: mpsc::Sender<InboundMessage>) -> Result<(), ChannelError> {
        let socket: SocketAddr = self.config.bind.parse().map_err(|e| {
            ChannelError::new(format!("invalid grpc bind {}: {e}", self.config.bind))
        })?;

        let service = InboundService {
            sender,
            paused: Arc::clone(&self.paused),
            shutdown: Arc::clone(&self.shutdown),
            auth: self.config.auth.clone(),
        };

        let mut builder = Server::builder();
        if let Some(identity) = self.load_inbound_identity()? {
            let tls = ServerTlsConfig::new().identity(identity);
            builder = builder
                .tls_config(tls)
                .map_err(|e| ChannelError::new(format!("grpc inbound tls config failed: {e}")))?;
        } else {
            tracing::warn!(channel = %self.config.name, bind = %self.config.bind, "grpc inbound channel starting without TLS");
        }

        builder
            .add_service(proto::runtime_channel_server::RuntimeChannelServer::new(
                service,
            ))
            .serve(socket)
            .await
            .map_err(|e| ChannelError::new(format!("grpc inbound server failed: {e}")))
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

#[derive(Clone)]
pub struct GrpcOutboundConfig {
    pub name: String,
    pub endpoint: String,
    pub tls_ca_cert_path: Option<String>,
}

#[derive(Clone)]
pub struct GrpcOutboundChannel {
    config: GrpcOutboundConfig,
    client: Arc<Mutex<Option<proto::runtime_channel_client::RuntimeChannelClient<Channel>>>>,
    shutdown: Arc<AtomicBool>,
}

impl GrpcOutboundChannel {
    pub fn new(config: GrpcOutboundConfig) -> Self {
        Self {
            config,
            client: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn client(
        &self,
    ) -> Result<proto::runtime_channel_client::RuntimeChannelClient<Channel>, ChannelError> {
        let mut guard = self.client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }

        let endpoint = Endpoint::from_shared(self.config.endpoint.clone())
            .map_err(|e| ChannelError::new(format!("invalid grpc endpoint: {e}")))?;
        let endpoint = if self.config.endpoint.starts_with("https://") {
            let mut tls = ClientTlsConfig::new();
            if let Some(path) = self.config.tls_ca_cert_path.as_deref() {
                let pem = std::fs::read(path).map_err(|e| {
                    ChannelError::new(format!("failed to read grpc CA cert `{path}`: {e}"))
                })?;
                tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(pem));
            }
            endpoint
                .tls_config(tls)
                .map_err(|e| ChannelError::new(format!("grpc tls config failed: {e}")))?
        } else {
            tracing::warn!(channel = %self.config.name, endpoint = %self.config.endpoint, "grpc outbound channel using plaintext endpoint");
            endpoint
        };
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| ChannelError::new(format!("failed grpc connect: {e}")))?;
        let client = proto::runtime_channel_client::RuntimeChannelClient::new(channel);
        *guard = Some(client.clone());
        Ok(client)
    }
}

impl GrpcInboundChannel {
    fn load_inbound_identity(&self) -> Result<Option<Identity>, ChannelError> {
        match (
            self.config.tls_cert_path.as_deref(),
            self.config.tls_key_path.as_deref(),
        ) {
            (Some(cert_path), Some(key_path)) => {
                let cert = std::fs::read_to_string(cert_path).map_err(|e| {
                    ChannelError::new(format!("failed to read grpc cert `{cert_path}`: {e}"))
                })?;
                let key = std::fs::read_to_string(key_path).map_err(|e| {
                    ChannelError::new(format!("failed to read grpc key `{key_path}`: {e}"))
                })?;
                Ok(Some(Identity::from_pem(cert, key)))
            }
            (None, None) => Ok(None),
            _ => Err(ChannelError::new(
                "grpc inbound TLS requires both tls_cert and tls_key",
            )),
        }
    }
}

#[async_trait]
impl OutboundChannel for GrpcOutboundChannel {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, msg: OutboundMessage) -> Result<DeliveryReceipt, ChannelError> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(ChannelError::new("channel is shut down"));
        }

        let mut client = self.client().await?;
        let response = client
            .send_inbound(Request::new(proto::InboundEnvelope {
                raw: msg.raw,
                content_type: msg.content_type,
            }))
            .await
            .map_err(|e| ChannelError::new(format!("grpc send failed: {e}")))?;

        Ok(DeliveryReceipt {
            id: response.into_inner().id,
        })
    }

    async fn shutdown(&self) -> Result<(), ChannelError> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn health(&self) -> Result<ChannelHealth, ChannelError> {
        Ok(ChannelHealth {
            ok: !self.shutdown.load(Ordering::Relaxed),
            message: Some("ok".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mx20022_channels::{OutboundChannel, OutboundMessage};

    use super::{GrpcInboundChannel, GrpcInboundConfig, GrpcOutboundChannel, GrpcOutboundConfig};

    #[tokio::test]
    async fn outbound_sends_to_inbound() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping grpc outbound/inbound test: {error}");
                return;
            }
            Err(error) => panic!("bind listener: {error}"),
        };
        let local_addr = listener.local_addr().expect("local addr");
        let inbound = GrpcInboundChannel::new(GrpcInboundConfig {
            name: "grpc-in".to_string(),
            bind: local_addr.to_string(),
            auth: mx20022_channels::auth::InboundAuthConfig::default(),
            tls_cert_path: None,
            tls_key_path: None,
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let runner = inbound.clone();
        tokio::spawn(async move {
            let _ = runner.run_with_listener(listener, tx).await;
        });

        // Wait for the server to be ready by polling a TCP connect instead
        // of a fixed sleep, which intermittently raced the tonic serve loop
        // under CI load.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(local_addr).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("grpc inbound should become ready within 2s");

        let outbound = GrpcOutboundChannel::new(GrpcOutboundConfig {
            name: "grpc-out".to_string(),
            endpoint: format!("http://{}", local_addr),
            tls_ca_cert_path: None,
        });

        let receipt = outbound
            .send(OutboundMessage {
                raw: "<Document/>".to_string(),
                content_type: "application/xml".to_string(),
            })
            .await
            .expect("send should succeed");
        assert_eq!(receipt.id, "accepted");

        let message = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("should receive inbound")
            .expect("message should be present");
        assert_eq!(message.raw, "<Document/>");
    }
}
