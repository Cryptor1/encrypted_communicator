//! Encryption keys and hashing algorithms.
//!
//! Since the&nbsp;crate does&nbsp;not&nbsp;implement custom struct which
//! represents RSA key, and uses `openssl::rsa::Rsa` from
//! the&nbsp;[`openssl`][1] crate, the&nbsp;RSA API is defined in
//! a&nbsp;separated sub&#x2011;crate.
//!
//! [1]: https://crates.io/crates/openssl

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
