use crate::session;
use rasn::prelude::ObjectIdentifier;
use std::num::ParseIntError;
use thiserror::Error;

pub trait ObjectIdentifierExt {
    fn is_within(&self, other: &Self) -> bool;

    fn parse(oid: impl AsRef<str>) -> Result<Self, ParseObjectIdentifierError>
    where
        Self: Sized;
}

impl ObjectIdentifierExt for ObjectIdentifier {
    /// Returns true if this OID is underneath/within another oid. For example
    /// the OID `.1.2.3` is within `.1.2`, but is not within `.1.2.4`, or
    /// `.1.2.3.4`.
    ///
    /// # Example
    /// ```
    /// use rasn::prelude::ObjectIdentifier;
    /// use crate::core_snmp::ObjectIdentifierExt;
    ///
    /// let oid = ObjectIdentifier::new(&[1, 2, 3]).unwrap();
    /// let other = ObjectIdentifier::new(&[1, 2]).unwrap();
    /// assert!(oid.is_within(other));
    ///
    /// let other = ObjectIdentifier::new(&[1, 2, 4]).unwrap();
    /// assert!(!oid.is_within(other));
    ///
    /// let other = ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap();
    /// assert!(!oid.is_within(other));
    /// ```
    fn is_within(&self, other: &Self) -> bool {
        // If the other OID is longer/more specific than this OID, then
        // this OID cannot be within the other OID.
        if self.len() < other.len() {
            return false;
        }
        self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }

    /// Attempts to parse an [`ObjectIdentifier`] from a string.
    ///
    /// # Example
    /// ```
    /// use rasn::prelude::ObjectIdentifier;
    /// use core_snmp::ObjectIdentifierExt;
    ///
    /// let oid = ObjectIdentifier::parse("1.2.3").unwrap();
    /// assert_eq!(oid, ObjectIdentifier::new(&[1, 2, 3]).unwrap());
    ///
    /// let oid = ObjectIdentifier::parse(".1.2.3").unwrap();
    /// assert_eq!(oid, ObjectIdentifier::new(&[1, 2, 3]).unwrap());
    /// ```
    fn parse(oid: impl AsRef<str>) -> Result<Self, ParseObjectIdentifierError> {
        let parts = oid
            .as_ref()
            .trim_start_matches('.')
            .split('.')
            .map(|s| s.parse())
            .collect::<Result<Vec<u32>, _>>()?;
        ObjectIdentifier::new(parts).ok_or(ParseObjectIdentifierError::InvalidObjectIdentifier)
    }
}

pub trait IntoObjectIdentifier {
    fn into(self) -> Result<ObjectIdentifier, ParseObjectIdentifierError>;
}

impl IntoObjectIdentifier for &str {
    fn into(self) -> Result<ObjectIdentifier, ParseObjectIdentifierError> {
        ObjectIdentifier::parse(self)
    }
}

impl IntoObjectIdentifier for ObjectIdentifier {
    fn into(self) -> Result<ObjectIdentifier, ParseObjectIdentifierError> {
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum ParseObjectIdentifierError {
    #[error("parsing sub-identifier: {0}")]
    ParsingSubIdentifier(#[from] ParseIntError),
    #[error("invalid object identifier")]
    InvalidObjectIdentifier,
}

impl From<ParseObjectIdentifierError> for session::Error {
    fn from(value: ParseObjectIdentifierError) -> Self {
        session::Error::InvalidObjectIdentifier(value)
    }
}
