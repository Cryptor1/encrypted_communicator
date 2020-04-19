//! Gathers conventions in form of `NegotiationKey` and `CommunicationKey`,
//! which describe encryption keys' properties required by this crate. Also
//! contains implementations for the&nbsp;mentioned traits, namely:
//! * `Rsa`, which implements `NegotiationKey`
//! * `Aes`, which implements `CommunicationKey`

mod aes;
mod communication_key;
mod error;
mod negotiation_key;
mod rsa;

pub use self::aes::Aes;
pub use self::rsa::{Rsa, RsaKeySize};
pub use self::error::{Error, ErrorKind};
pub use crate::secret::communication_key::CommunicationKey;
pub use crate::secret::negotiation_key::NegotiationKey;
