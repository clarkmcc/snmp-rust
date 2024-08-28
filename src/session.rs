use crate::dispatcher::{DispatchError, SessionDispatcher};
use crate::message::Respondable;
use crate::oid::ParseObjectIdentifierError;
use num_bigint::BigInt;
use rasn::{ber, Decode, Encode};
use rasn_smi::v1::ObjectSyntax;
use rasn_snmp::v1;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io;
use tokio::net::UdpSocket;

/// Restricts a session to a specific version of SNMP and provides the necessary
/// message and option types supported by that version of SNMP.
pub(super) trait VersionedSession {
    /// The type of SNMP message used by this version of SNMP. An SNMPv1 session
    /// for example would use the [`v1::Message`] type.
    type Message;

    /// The options required to use this version of SNMP. For SNMPv1 this might
    /// be the community string, while for SNMPv3, this might be the security
    /// parameters.
    type Options;
}

/// Options required to create an SNMP session generic over the SNMP version-specific
/// options.
pub struct SessionOptions<O> {
    pub target: SocketAddr,
    pub timeout: Duration,
    pub snmp: O,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid object identifier: {0}")]
    InvalidObjectIdentifier(ParseObjectIdentifierError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("encoding error: {0}")]
    EncodingError(ber::enc::EncodeError),

    #[error("unexpected response: {0}")]
    UnexpectedResponseType(String),

    #[error("unsupported value type: {0:?}")]
    UnsupportedValueType(ObjectSyntax),
}

impl From<DispatchError> for Error {
    fn from(value: DispatchError) -> Self {
        match value {
            DispatchError::Io(err) => Error::Io(err),
            DispatchError::Encoding(err) => Error::EncodingError(err),
        }
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

pub struct Session<Version: VersionedSession> {
    /// The session itself wrapped in an `Arc` to allow for passing the session
    /// between threads.
    pub(super) inner: Arc<SessionInner<Version>>,
}

impl<V: VersionedSession> Clone for Session<V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub(super) struct SessionInner<Version: VersionedSession> {
    /// Dispatcher is responsible for sending and receiving SNMP messages.
    /// It allows session to be thread-safe by correlating concurrent requests
    /// using the SNMP request ID.
    pub(super) dispatcher: SessionDispatcher<Version::Message>,

    /// The next request ID to use. Each SNMP request should use [`AtomicU16::fetch_add`]
    /// to get a unique request ID and increment it for the next request. Unique IDs are
    /// on a per-session basis
    pub(super) request_id: AtomicU16,

    /// SNMP options to send in each of the SNMP requests (i.e. community string).
    pub(super) options: SessionOptions<Version::Options>,
}

impl<V: VersionedSession> Session<V> {
    /// Returns the next request ID to use for an SNMP request.
    pub(super) fn next_request_id(&self) -> BigInt {
        BigInt::from(self.inner.request_id.fetch_add(1, Ordering::SeqCst))
    }
}

impl<V: VersionedSession> Session<V>
where
    V::Message: Encode + Decode + Respondable + Send + Clone + 'static,
{
    pub(super) async fn new(options: SessionOptions<V::Options>) -> io::Result<Session<V>> {
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        let dispatcher = SessionDispatcher::new(socket, options.target, options.timeout);
        dispatcher.spawn_receiver();
        Ok(Self {
            inner: Arc::new(SessionInner {
                dispatcher,
                options,
                request_id: AtomicU16::new(1),
            }),
        })
    }
    
    /// Sends a message and returns the response if one was received within the timeout.
    pub(super) async fn send(&self, message: V::Message) -> Result<V::Message, Error> {
        let token = self
            .inner
            .dispatcher
            .send(self.inner.options.timeout, message)
            .await?;

        // If we get a RecvError, it means the timeout has expired and the sender was dropped
        token
            .await
            .map_err(|_| Error::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout")))
    }
}
