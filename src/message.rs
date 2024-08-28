use num_bigint::BigInt;
use rasn_snmp::{v1, v2, v2c, v3};

/// A trait that describes messages that can be sent and expect to receive
/// a response from an SNMP agent. SNMP messages that implement this trait
/// can provide a request ID which is used to match responses to requests.
pub(super) trait Respondable {
    fn request_id(&self) -> Option<BigInt>;
}

impl Respondable for v3::Message {
    fn request_id(&self) -> Option<BigInt> {
        Some(self.global_data.message_id.clone())
    }
}

impl Respondable for v1::Message<v1::Pdus> {
    fn request_id(&self) -> Option<BigInt> {
        match &self.data {
            v1::Pdus::GetRequest(pdu) => Some(pdu.0.request_id.clone()),
            v1::Pdus::GetNextRequest(pdu) => Some(pdu.0.request_id.clone()),
            v1::Pdus::GetResponse(pdu) => Some(pdu.0.request_id.clone()),
            v1::Pdus::SetRequest(pdu) => Some(pdu.0.request_id.clone()),
            v1::Pdus::Trap(_) => None,
        }
    }
}

impl Respondable for v2c::Message<v2::Pdus> {
    fn request_id(&self) -> Option<BigInt> {
        match &self.data {
            v2::Pdus::GetRequest(pdu) => Some(pdu.0.request_id.into()),
            v2::Pdus::GetNextRequest(pdu) => Some(pdu.0.request_id.into()),
            v2::Pdus::Response(pdu) => Some(pdu.0.request_id.into()),
            v2::Pdus::SetRequest(pdu) => Some(pdu.0.request_id.into()),
            _ => None,
        }
    }
}