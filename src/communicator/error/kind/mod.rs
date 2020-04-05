use crate::data::Uid;
use crate::secret::Error;

/// Kind of error represented by `secret::Error`.
#[derive(Debug)]
pub enum Kind {
	/// Obtained raw bytes are of inappropriate structure/content.
	InappropriateData,
	/// Failed to generate encryption key.
	KeyGenerationFailure,
	/// Failed to decrypt obtained from another communicator `CommunicationKey`.
	///
	/// `Uid` &#x2013; Unique identifier of another communicator.
	KeyDecryption(Uid),
	/// Outgoing communication request has been refused since another
	/// communicator perceives connection as already established.
	///
	/// `Uid` &#x2013; Unique identifier of another communicator which refused
	/// establish&#x2011;connection request.
	AlreadyEstablished(Uid),
	/// Failed to decrypt the&nbsp;received encrypted data.
	DataDecryption,
	/// Failed to encrypt data.
	///
	/// `Error` &#x2013; Encryption error which occurred.
	DataEncryption(Error),
	/// A connection with a&nbsp;given communicator has been already requested.
	AlreadyRequested,
	/// There is no&nbsp;communication key present to communicate with another
	/// communicator with `Uid` unique identifier.
	CommunicationKeyAbsent(Uid),
	/// Failed to generate unique identifier for a&nbsp;given communicator.
	UidGeneration,
}
