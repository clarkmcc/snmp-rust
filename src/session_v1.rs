use crate::oid::IntoObjectIdentifier;
use crate::oid::ObjectIdentifierExt;
use crate::session::{Error, Session, SessionOptions, VersionedSession};
use rasn::prelude::{ObjectIdentifier, OctetString};
use rasn_smi::v1::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v1;
use rasn_snmp::v1::{GetNextRequest, GetRequest, Message, Pdus, VarBind};
use tokio::io;

/// An implementation of [`VersionedSession`] for SNMPv1.
pub struct V1;

impl VersionedSession for V1 {
    type Message = Message<Pdus>;
    type Options = V1Options;
}

pub struct V1Options {
    pub community: String,
}

impl Session<V1> {
    /// Constructs a new SNMPv1 session.
    pub async fn v1(options: SessionOptions<V1Options>) -> io::Result<Session<V1>> {
        Self::new(options).await
    }

    /// Performs an SNMPv1 GET request using the provided OID.
    pub async fn get<S>(&self, oid: S) -> Result<VarBind, Error>
    where
        S: AsRef<str>,
    {
        let mut results = self.get_bulk([oid]).await?;
        results.pop().ok_or(Error::UnexpectedResponseType(
            "Expected at least one result, got none".to_string(),
        ))
    }

    /// Performs an SNMPv1 GET request using the provided OIDs.
    pub async fn get_bulk<I, S>(&self, oids: I) -> Result<Vec<VarBind>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // Convert each oid into variable bindings
        let bindings = oids
            .into_iter()
            .map(|oid| {
                ObjectIdentifier::parse(oid.as_ref()).map(|oid| VarBind {
                    name: oid,
                    value: ObjectSyntax::Simple(SimpleSyntax::Empty),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bindings_len = bindings.len();

        // Construct the SNMPv1 message
        let message = Message {
            version: 1.into(),
            community: OctetString::from(self.inner.options.snmp.community.clone()),
            data: Pdus::GetRequest(GetRequest(v1::Pdu {
                request_id: self.next_request_id(),
                variable_bindings: bindings,
                error_index: Default::default(),
                error_status: Default::default(),
            })),
        };

        // Send the message and wait for the response
        match self.send(message).await?.data {
            Pdus::GetResponse(response) => {
                let results = response.0.variable_bindings.to_vec();
                if results.len() != bindings_len {
                    Err(Error::UnexpectedResponseType(format!(
                        "Expected {} results, got {}",
                        bindings_len,
                        results.len()
                    )))
                } else {
                    Ok(results)
                }
            }
            data => Err(Error::UnexpectedResponseType(format!(
                "Expected GetResponse, got {:?}",
                data
            ))),
        }
    }

    /// Performs an SNMPv1 GET NEXT request, returning the next [`VarBind`] in the MIB.
    pub async fn get_next<T>(&self, oid: T) -> Result<VarBind, Error>
    where
        T: IntoObjectIdentifier,
    {
        let message = Message {
            version: 1.into(),
            community: OctetString::from(self.inner.options.snmp.community.clone()),
            data: Pdus::GetNextRequest(GetNextRequest(v1::Pdu {
                request_id: self.next_request_id(),
                variable_bindings: vec![oid.into().map(|oid| VarBind {
                    name: oid,
                    value: ObjectSyntax::Simple(SimpleSyntax::Empty),
                })?],
                error_index: Default::default(),
                error_status: Default::default(),
            })),
        };

        // Send the message and wait for the response
        match self.send(message).await?.data {
            Pdus::GetResponse(response) => Ok(response.0.variable_bindings.to_vec().pop().ok_or(
                Error::UnexpectedResponseType("Expected at least one result, got none".to_string()),
            )?),
            data => Err(Error::UnexpectedResponseType(format!(
                "Expected GetResponse, got {:?}",
                data
            ))),
        }
    }

    pub async fn walk<T>(&self, root: T) -> Result<Vec<VarBind>, Error>
    where
        T: IntoObjectIdentifier,
    {
        let root = root.into()?;
        let mut next = root.clone();
        let mut results = Vec::new();

        loop {
            let result = self.get_next(next.clone()).await?;
            if result.name.is_within(&root) {
                next = result.name.clone();
                results.push(result);
            } else {
                break;
            }
        }

        Ok(results)
    }
}
