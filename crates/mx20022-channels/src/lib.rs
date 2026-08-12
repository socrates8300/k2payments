// Copyright (C) 2026 mx20022-runtime contributors
// SPDX-License-Identifier: AGPL-3.0-only

use async_trait::async_trait;

pub mod auth;

/// Message envelope delivered by inbound transports into the runtime.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub raw: String,
    pub content_type: String,
}

/// Message envelope emitted by the runtime into outbound transports.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub raw: String,
    pub content_type: String,
}

/// Delivery acknowledgement returned by outbound transports.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    pub id: String,
}

/// Lightweight channel health status.
#[derive(Debug, Clone)]
pub struct ChannelHealth {
    pub ok: bool,
    pub message: Option<String>,
}

/// Receives messages from an external source and forwards them to the runtime.
#[async_trait]
pub trait InboundChannel: Send + Sync {
    fn name(&self) -> &str;
    async fn run(
        &self,
        sender: tokio::sync::mpsc::Sender<InboundMessage>,
    ) -> Result<(), ChannelError>;
    async fn shutdown(&self) -> Result<(), ChannelError>;
    async fn health(&self) -> Result<ChannelHealth, ChannelError>;
    async fn pause(&self) -> Result<(), ChannelError>;
    async fn resume(&self) -> Result<(), ChannelError>;
}

/// Sends runtime-produced messages to an external destination.
#[async_trait]
pub trait OutboundChannel: Send + Sync {
    fn name(&self) -> &str;
    async fn send(&self, msg: OutboundMessage) -> Result<DeliveryReceipt, ChannelError>;
    async fn shutdown(&self) -> Result<(), ChannelError>;
    async fn health(&self) -> Result<ChannelHealth, ChannelError>;
}

#[derive(Debug, thiserror::Error)]
#[error("channel error: {message}")]
pub struct ChannelError {
    message: String,
}

impl ChannelError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Poll `addr` until a TCP connect succeeds or `timeout` elapses.
pub async fn wait_for_tcp(addr: impl AsRef<str>, timeout: std::time::Duration) -> bool {
    let addr = addr.as_ref().to_string();
    tokio::time::timeout(timeout, async {
        loop {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}
