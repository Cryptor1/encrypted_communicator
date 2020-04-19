use crate::data::Uid;

/// Incoming data after being processed.
#[derive(Debug)]
pub enum ProcessedData {
	/// Decrypted data which should be further processed by the&nbsp;implementor
	/// code.
	/// # Parameters
	/// * `Uid` &ndash; Unique identifier of `Communicator` which prepared this
	/// data.
	Communication(Vec<u8>, Uid),
	/// Service data which needs to be transmitted back to the&nbsp;sender
	/// communicator.
	/// # Parameters
	/// * `Uid` &ndash; Unique identifier of `Communicator` which prepared this
	/// service data.
	Service(Vec<u8>, Uid),
	/// New encrypted communication has been successfully established.
	///
	/// `Uid` &#x2013; Unique identifier of another communicator,
	/// a&nbsp;communication with which has been established.
	ConnectionEstablished(Uid),
	/// No data to process.
	None,
}
