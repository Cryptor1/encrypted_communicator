use crate::data::Uid;

/// Incoming data after being processed.
#[derive(Debug)]
pub enum ProcessedData {
	/// Decrypted data which should be further processed by the&nbsp;implementor
	/// code.
	Communication(Vec<u8>),
	/// Service data which needs to be transmitted back to the&nbsp;sender
	/// communicator.
	Service(Vec<u8>),
	/// New encrypted communication has been successfully established.
	///
	/// `Uid` &#x2013; Unique identifier of another communicator,
	/// a&nbsp;communication with which has been established.
	ConnectionEstablished(Uid),
	/// No data to process.
	None,
}
