use crate::message::Respondable;
use num_bigint::BigInt;
use object_pool::{Reusable, ReusableOwned};
use rasn::ber::enc::EncoderOptions;
use rasn::error::{DecodeError, EncodeError};
use rasn::{ber, Decode, Decoder, Encode, Encoder};
use rasn_snmp::v1::Pdus;
use rasn_snmp::{v1, v2c, v3};
use std::cell::OnceCell;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::oneshot::{Receiver, Sender};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio::{io, spawn};
use tracing::{error, warn};

const MAX_UDP_PACKET_SIZE: usize = 65507;

/// The data type that will be sent to subscribers when a response is received.
type SubscriptionData<M> = M;

/// A thread-safe communication channel based on request IDs.
///
/// When a message is sent, a caller can subscribe to the response by providing
/// a request ID. If the response is received before the timeout elapses, then
/// the subscriber will be notified with the response data.
#[derive(Clone)]
struct Subscribers<M> {
    inner: Arc<Mutex<HashMap<BigInt, Sender<SubscriptionData<M>>>>>,
}

impl<M> Default for Subscribers<M> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<M> Subscribers<M>
where
    M: Send + Clone + 'static,
{
    /// Subscribes to a response with the given request ID. If no data is received before
    /// the timeout elapses, then the sender will be notified with an error.
    ///
    /// todo: duplicate request IDs should be handled
    async fn subscribe(&self, id: BigInt, timeout: Duration, sender: Sender<SubscriptionData<M>>) {
        self.inner.lock().await.insert(id.clone(), sender);

        // Spawn a task that will kill and remove the subscriber after the timeout has elapsed.
        let subs = self.clone();
        spawn(async move {
            sleep(timeout).await;
            subs.inner.lock().await.remove(&id);
        });
    }

    /// Checks to see if there's an active subscriber for the given request ID, and if so
    /// sends the data to the subscriber.
    async fn notify(&self, id: BigInt, data: M) {
        if let Some(tx) = self.inner.lock().await.remove(&id) {
            // We ignore the result of the send operation, as the receiver might
            // have been dropped which means that they really don't care about
            // this data any ways.
            let _ = tx.send(data);
        }
    }
}

/// The maximum size of a packet that can be received. Users may choose to tune
/// this if they're willing to drop larger packets in exchange for lower memory
/// usage.
pub enum PacketSizeLimit {
    Max,
    Custom(u16),
}

impl Default for PacketSizeLimit {
    fn default() -> Self {
        Self::Max
    }
}

impl PacketSizeLimit {
    pub fn limit(&self) -> usize {
        match self {
            Self::Max => u16::MAX as usize,
            Self::Custom(limit) => *limit as usize,
        }
    }
}

/// A dispatcher sends and receives messages `M` over a UDP socket. It is responsible
/// for encoding and decoding the messages, and matching responses to requests.
pub(super) struct SessionDispatcher<M> {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    timeout: Duration,
    subs: Subscribers<M>,
    receiver_started: AtomicBool,
}

/// An error that can occur when dispatching messages.
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("encoding error: {0:?}")]
    Encoding(EncodeError),
}

impl<M> SessionDispatcher<M>
where
    M: Encode + Decode + Respondable + Send + Clone + 'static,
{
    pub(super) fn new(socket: Arc<UdpSocket>, target: SocketAddr, timeout: Duration) -> Self {
        Self {
            socket,
            timeout,
            target,
            receiver_started: AtomicBool::new(false),
            subs: Subscribers::default(),
        }
    }

    /// Sends a message and returns a [`Receiver`] that will receive the response.
    /// The receiver will receive either the data, or an empty error indicating that a timeout
    /// has occurred.
    pub(super) async fn send(
        &self,
        timeout: Duration,
        message: M,
    ) -> Result<Receiver<SubscriptionData<M>>, DispatchError> {
        if let Some(request_id) = message.request_id() {
            let bytes = encode_message(message).map_err(DispatchError::Encoding)?;
            let (tx, rx) = oneshot::channel();
            self.subs.subscribe(request_id, timeout, tx).await;
            self.socket.send_to(&bytes, &self.target).await?;
            Ok(rx)
        } else {
            todo!("implement sending SNMP messages without request id");
        }
    }

    /// Spawns a task that will receive messages from the socket and notify subscribers.
    /// This function is idempotent and will only spawn a single receiver task.
    pub(super) fn spawn_receiver(&self) {
        if !self.receiver_started.swap(true, Ordering::SeqCst) {
            let socket = self.socket.clone();
            let subscribers = self.subs.clone();
            spawn(async move {
                receiver(socket, subscribers).await;
            });
        }
    }
}

/// Receives messages from the socket, decodes them, and notifies subscribers
/// of the received data. Currently, this allocates a new buffer for each message
/// on the stack with a [`MAX_UDP_PACKET_SIZE`] limit. This should eventually be replaced
/// with a buffer pool and re-sizable buffers.
async fn receiver<M>(socket: Arc<UdpSocket>, subscribers: Subscribers<M>)
where
    M: Decode + Respondable + Send + Clone + 'static,
{
    let mut buf = [0u8; MAX_UDP_PACKET_SIZE];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, _)) => {
                if size == MAX_UDP_PACKET_SIZE {
                    warn!("Received a message that exceeds the buffer size limit");
                    continue;
                }
                match decode_message(&buf[..size]) {
                    // We received a message with a message ID, so we can notify the subscriber.
                    Ok((Some(id), message)) => {
                        subscribers.notify(id, message).await;
                    }
                    // We received a valid SNMP message but could not obtain a request ID (maybe
                    // someone accidentally sent us a trap?). So just ignore it.
                    Ok((None, _)) => {
                        warn!("Received SNMP message without request id");
                    }
                    // We couldn't decode the message, so just log and continue.
                    Err(error) => {
                        warn!("Failed to decode SNMP message: {}", error);
                    }
                }
            }
            // There was a failure reading data from the UDP socket. This could happen for a variety
            // of reasons, but let's not keep trying to read if the error is fatal.
            Err(error) => {
                warn!("Failed to receive SNMP message: {}", error);
                match error.kind() {
                    ErrorKind::PermissionDenied
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::BrokenPipe
                    | ErrorKind::Unsupported
                    | ErrorKind::OutOfMemory => {
                        error!(
                            "Failed to receive SNMP message, shutting down receiver: {}",
                            error
                        );
                        break;
                    }
                    _ => continue,
                }
            }
        };
    }
}

/// Encodes a message into a byte buffer using the BER encoding.
fn encode_message<'pool, M: Encode>(message: M) -> Result<Vec<u8>, EncodeError> {
    let mut enc = ber::enc::Encoder::new(EncoderOptions::ber());
    message.encode(&mut enc)?;
    Ok(enc.output())
}

/// Decodes a message from a byte buffer using the BER encoding.
fn decode_message<M: Decode + Respondable>(buf: &[u8]) -> Result<(Option<BigInt>, M), DecodeError> {
    let message: M = ber::decode(&buf)?;
    Ok((message.request_id(), message))
}
