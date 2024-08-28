use crate::session::{Session, SessionOptions, VersionedSession};
use rasn_snmp::v2::Pdus;
use rasn_snmp::v2c::Message;
use tokio::io;

/// An implementation of [`VersionedSession`] for SNMPv2.
pub struct V2;

impl VersionedSession for V2 {
    type Message = Message<Pdus>;
    type Options = V2Options;
}

pub struct V2Options {
    pub community: String,
}

impl Session<V2> {
    /// Constructs a new SNMPv2 session.
    pub async fn v2(options: SessionOptions<V2Options>) -> io::Result<Session<V2>> {
        Self::new(options).await
    }
}
