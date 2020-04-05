//! Instances which form and define a&nbsp;given communication session header,
//! which in&nbsp;turn defines the&nbsp;conventions used to communicate between
//! instances of Encrypted&nbsp;Communicator.

mod error;
mod operation;
mod uid;
mod version;

pub use self::error::Error;
pub use self::error::Kind as ErrorKind;
pub use self::operation::Operation;
pub use self::operation::OperationError;
pub use self::operation::ResponseErrorType;
pub use self::uid::Uid;
pub use self::version::Version;

use serde_json;
use byteorder::ByteOrder;
use byteorder::BigEndian;

use self::operation::ErrorKind as OperationErrorKind;

/// A given communication session data which defines the&nbsp;conventions used
/// to communicate between instances of Encrypted&nbsp;Communicator and carries
/// the&nbsp;transmitted content.
#[derive(Debug)]
pub struct Data {
	/// Communication protocol version according to which an&nbsp;instance of
	/// this struct is going to be structured. Basically it defines fields which
	/// are expected to be present in this struct.
	version: Version,
	/// Unique identifier of another communicator for which an&nbsp;instance of
	/// this struct is designated.
	uid: Uid,
	/// Operation, in terms of communication session, being represented by
	/// an&nbsp;instance of this struct.
	operation: Operation,
}

impl Data {
	/// Creates new `Data` instance.
	/// # Parameters
	/// * `version` &ndash; Communication protocol version according to which
	/// data is going to be structured.
	/// * `uid` &ndash; Unique identifier of another communicator for which
	/// an&nbsp;instance of returned struct is designated.
	/// * `operation` &ndash; Operation, in terms of communication session,
	/// which will be represented by an&nbsp;instance of the&nbsp;returned
	/// struct.
	pub fn new(version: Version, uid: &Uid, operation: Operation) -> Self {
		return Self { version, uid: uid.clone(), operation }
	}

	/// Evaluates raw bytes data into convenient struct used by the&nbsp;crate.
	/// # Possible errors
	/// * `data::error::kind::ErrorKind::NoSize`
	/// * `data::error::kind::ErrorKind::Json`
	/// * `data::error::kind::ErrorKind::HeaderData`
	/// * `data::error::kind::ErrorKind::ContentData`
	pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
		// The `data` parameter is expected to be of following structure:
		// 1) The first 4 bytes represent a size of the JSON structure
		// (represented by `RoughHeader` struct) size.
		// 2) Next n bytes (where n has been determined in the step 1) represent
		// the mentioned JSON data structure.
		// 3) Remaining bytes represent transmitted content.

		let bytes_in_u32: usize = 4;
		// Covered with `data_obtain_from_bytes_incorrect_data()` test
		if data.len() < bytes_in_u32 { return Err(error::new(ErrorKind::NoSize)) }
		let json_size: usize = BigEndian::read_u32(&data[0..bytes_in_u32]) as usize;
		let json: RoughHeader = match serde_json::from_slice(
			&data[bytes_in_u32..bytes_in_u32 + json_size],
		) {
			Ok(header) => header,
			// Covered with `data_obtain_from_bytes_incorrect_data()` test
			Err(err) => return Err(error::new(ErrorKind::Json(err.classify()))),
		};
		let version: Version = version::define_version(&json.version)?;
		let uid: Uid = match Uid::from_string(&json.uid) {
			Ok(uid) => uid,
			// Covered with `data_obtain_from_bytes_incorrect_uid()` test
			Err(_) => return Err(error::new(ErrorKind::HeaderData)),
		};
		let operation: Operation = match operation::define_operation(
			&json.operation,
			&data[(bytes_in_u32 + json_size)..],
		) {
			Ok(operation) => operation,
			Err(err) => {
				match err.kind() {
					OperationErrorKind::IncorrectEstablishData => {
						// Covered with
						// `data_obtain_from_bytes_incorrect_establish_data()`
						// test
						return Err(error::new(ErrorKind::HeaderData))
					},
					OperationErrorKind::UndefinedOperation => {
						// Covered with
						// `data_obtain_from_bytes_undefined_operation()` test
						return Err(error::new(ErrorKind::ContentData))
					},
				}
			},
		};
		return Ok(Self { version, uid: uid, operation })
	}

	/// Converts communication session data into raw bytes. These raw bytes may
	/// be evaluated back to the&nbsp;`Data` structure by feeding them into
	/// `from_bytes()` method.
	/// # Possible errors
	/// * `data::error::kind::ErrorKind::Json`
	pub fn convert_to_bytes(self) -> Result<Vec<u8>, Error> {
		// The bytes structure which is going to be returned is described at
		// the beginning of the `from_bytes()` method

		let rough_header = RoughHeader {
			version: version::version_as_string(self.version),
			uid: self.uid.plain_value(),
			operation: operation::define_operation_as_string(&self.operation),
		};
		let header = match serde_json::to_vec(&rough_header) {
			Ok(raw_bytes) => raw_bytes,
			Err(err) => return Err(error::new(ErrorKind::Json(err.classify()))),
		};
		let raw_data = match self.operation {
			Operation::Establish(negotiation_key) => negotiation_key.public_part(),
			Operation::Response(result) => {
				match result {
					Ok(data) => data,
					Err(err) => operation::define_error_type_as_string(err).into_bytes(),
				}
			},
			Operation::Communicate(to_transmit) => to_transmit,
		};

		let bytes_in_u32 = 4;
		let header_size: u32 = header.len() as u32;
		let to_return_capacity = bytes_in_u32 + header_size as usize;

		let mut to_return = Vec::with_capacity(to_return_capacity);
		let mut header_size_in_bytes = vec![0; bytes_in_u32 as usize];
		BigEndian::write_u32(&mut header_size_in_bytes, header_size);

		to_return.extend(header_size_in_bytes);
		to_return.extend(header);
		to_return.extend(raw_data);
		return Ok(to_return)
	}

	/// Returns a&nbsp;unique identifier of another communicator.
	pub fn get_uid(&self) -> &Uid { return &self.uid }


	/// Returns an operation being performed in a&nbsp;given communication
	/// session.
	pub fn get_operation(&self) -> &Operation { return &self.operation }
}

/// A rough communication session header obtained from parsing raw bytes slice.
/// In order for obtained data to be used in the&nbsp;crate, this struct should
/// be converted to [Data](struct.Data.html) instance. See
/// `data::Data::from_bytes` method.
#[derive(Serialize, Deserialize)]
struct RoughHeader {
	/// Communication version which defines the&nbsp;rules used to communicate
	/// between instances of the&nbsp;Encrypted&nbsp;Communicator. Follows
	/// semver pattern.
	version: String,
	/// Unique identifier of another communicator in the&nbsp;form of
	/// SHA&#x2011;256 hash.
	uid: String,
	/// Operation being performed in a&nbsp;given communication session.
	operation: String,
}

#[cfg(test)]
mod tests {
	use byteorder::BigEndian;
	use byteorder::ByteOrder;
	use serde_json::error::Category;
	use crate::data::{Data, RoughHeader};
	use crate::data::Error;
	use crate::data::error;
	use crate::data::ErrorKind;
	use crate::data::{operation, Operation};
	use crate::data::Uid;
	use crate::data::{version, Version};

	#[test]
	/// Tests `Data::new` function's happy path.
	fn data_new_happy_path() {
		create_data();
	}

	/// Tests `Data::from_bytes()` function's happy path.
	#[test]
	fn data_from_bytes_happy_path() {
		let original_data: Data = create_data();
		let serialized_data: Vec<u8> = original_data.convert_to_bytes()
			.expect("Should convert `Data` object to bytes");
		Data::from_bytes(&serialized_data).expect("Should deserialize `Data` object");
	}

	/// Tests `Data::from_bytes()` function's error cases:
	///
	/// &#x2022; Passes data with less than 4 bytes size.
	///
	/// &#x2022; Passes JSON binary data with less than expected size.
	#[test]
	fn data_from_bytes_incorrect_data() {
		// Check that passing data less than 4 bytes produces `ErrorKind::NoSize`
		// error
		let no_size_data: Vec<u8> = vec![1, 2, 3];
		let result: Error = Data::from_bytes(&no_size_data).expect_err("Error result is expected");
		assert_eq!(result, error::new(ErrorKind::NoSize));

		// Check that passing bytes with JSON data less than its expected size
		// produces error
		let bytes_in_u32: usize = 4;
		let dummy_header_size: usize = 100;
		let to_return_capacity: usize = bytes_in_u32 + dummy_header_size;
		let mut header_size_as_bytes: Vec<u8> = vec![0; bytes_in_u32];
		BigEndian::write_u32(&mut header_size_as_bytes, bytes_in_u32 as u32);
		let json_data: Vec<u8> = vec![0; dummy_header_size as usize];
		let mut incorrect_json_data: Vec<u8> = Vec::with_capacity(to_return_capacity);
		incorrect_json_data.extend(header_size_as_bytes);
		incorrect_json_data.extend(json_data);
		let result: Error = Data::from_bytes(&incorrect_json_data)
			.expect_err("Error result is expected");
		assert_eq!(result, error::new(ErrorKind::Json(Category::Syntax)));
	}

	/// Tests `Data::from_bytes()` function's error path. Passes binary JSON
	/// data which carries incorrect value for `data::Uid`.
	#[test]
	fn data_from_bytes_incorrect_uid() {
		let operation: String = operation::define_operation_as_string(
			&Operation::Communicate(vec![10, 20, 30]),
		);
		let header: RoughHeader = RoughHeader {
			version: version::version_as_string(Version::Ver0_1),
			uid: "Incorrect unique identifier".to_string(),
			operation,
		};
		let header: Vec<u8> = serde_json::to_vec(&header)
			.expect("Failed to serialize header object into raw bytes");
		let mut header_binary: Vec<u8> = Vec::new();
		let bytes_in_u32: usize = 4;
		let mut header_size_as_bytes: Vec<u8> = vec![0; bytes_in_u32];
		BigEndian::write_u32(&mut header_size_as_bytes, header.len() as u32);

		header_binary.extend(header_size_as_bytes);
		header_binary.extend(header);
		let deserialization_error: Error = Data::from_bytes(header_binary.as_slice())
			.expect_err(
				"Serialized data has been deserialized into data object despite having \
					incorrect unique identifier stored",
			);
		match deserialization_error.kind() {
			ErrorKind::HeaderData => (),
			incorrect_error => {
				panic!(
					"Incorrect error type, `{:?}`, has been returned as the result of \
						deserializing a JSON object which carries incorrect unique identifier",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Data::from_bytes()` function's error path. Passes binary data
	/// which carries incorrect establish&#x2011;request data.
	#[test]
	fn data_from_bytes_incorrect_establish_data() {
		let header: RoughHeader = RoughHeader {
			version: version::version_as_string(Version::Ver0_1),
			uid: Uid::generate_totally_unique()
				.expect("Failed to generate unique identifier").plain_value(),
			operation: "establish".to_string(),
		};
		let header: Vec<u8> = serde_json::to_vec(&header)
			.expect("Failed to serialize header object into raw bytes");
		let mut binary_data: Vec<u8> = Vec::new();
		let bytes_in_u32: usize = 4;
		let mut header_size_as_bytes: Vec<u8> = vec![0; bytes_in_u32];
		BigEndian::write_u32(&mut header_size_as_bytes, header.len() as u32);

		binary_data.extend(header_size_as_bytes);
		binary_data.extend(header);
		binary_data.extend(vec![10, 20, 30]);
		let deserialization_error: Error = Data::from_bytes(binary_data.as_slice())
			.expect_err(
				"Serialized data has been deserialized into data object despite having \
					incorrect establish-request data stored",
			);
		match deserialization_error.kind() {
			ErrorKind::HeaderData => (),
			incorrect_error => {
				panic!(
					"Incorrect error type, `{:?}`, has been returned as the result of \
						deserializing a data which carries incorrect establish-request data",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Data::from_bytes()` function's error path. Passes binary
	/// JSON data which carries incorrect `operation` type.
	#[test]
	fn data_from_bytes_undefined_operation() {
		let header: RoughHeader = RoughHeader {
			version: version::version_as_string(Version::Ver0_1),
			uid: Uid::generate_totally_unique()
				.expect("Failed to generate unique identifier").plain_value(),
			operation: "incorrect operation identifier".to_string(),
		};
		let header: Vec<u8> = serde_json::to_vec(&header)
			.expect("Failed to serialize header object into raw bytes");
		let mut header_binary: Vec<u8> = Vec::new();
		let bytes_in_u32: usize = 4;
		let mut header_size_as_bytes: Vec<u8> = vec![0; bytes_in_u32];
		BigEndian::write_u32(&mut header_size_as_bytes, header.len() as u32);

		header_binary.extend(header_size_as_bytes);
		header_binary.extend(header);
		let deserialization_error: Error = Data::from_bytes(header_binary.as_slice())
			.expect_err(
				"Serialized data has been deserialized into data object despite having \
					incorrect `operation` type stored",
			);
		match deserialization_error.kind() {
			ErrorKind::ContentData => (),
			incorrect_error => {
				panic!(
					"Incorrect error type, `{:?}`, has been returned as the result \
						of deserializing a data which carries incorrect `operation` type",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Data::convert_to_bytes()` function's happy path.
	#[test]
	fn data_convert_to_bytes() {
		create_data()
			.convert_to_bytes()
			.expect("Should convert `Data` object to raw bytes");
	}

	/// Tests `Data::uid()` function's happy path.
	#[test]
	fn data_get_uid() { create_data().get_uid(); }

	/// Tests `Data::get_operation()` function's happy path.
	#[test]
	fn data_get_operation() { create_data().get_operation(); }

	/// 1. Create `Data` object.
	/// 1. Serialize created `Data` object.
	/// 1. Deserialize `Data` object.
	/// 1. Compare all deserialized object's fields to original ones.
	///
	/// _Expected:_ Compared fields to be equal.
	#[test]
	fn data_convert_to_bytes_and_back() {
		let version: Version = Version::Ver0_1;
		let uid: Uid = Uid::generate_totally_unique()
			.expect("Should generate unique identifier");
		let operation_data: Vec<u8> = vec![10, 20, 30];
		let operation: Operation = Operation::Communicate(operation_data.clone());

		let data: Data = Data::new(version, &uid, operation);
		let data_as_bytes: Vec<u8> = data.convert_to_bytes()
			.expect("Should convert `Data` object to raw bytes");

		let data: Data = Data::from_bytes(&data_as_bytes)
			.expect("Should convert raw bytes back to `Data` object");
		assert_eq!(
			data.version, version,
			"Deserialized `Data` object should have `Version` equal to original"
		);
		assert_eq!(
			data.get_uid(), &uid,
			"Deserialized `Data` object should have `Uid` equal to original"
		);
		match data.get_operation() {
			Operation::Communicate(raw_data) => {
				assert_eq!(*raw_data, operation_data,
					"Deserialized `Data` object should contain `Operation` \
						content equal to original"
				);
			},
			_ => panic!(
				"Deserialized `Data` object should contain `Operation` type \
					equal to original"
			)
		}
	}

	fn create_data() -> Data {
		let unique_identifier: Uid = Uid::generate_totally_unique()
			.expect("Should generate unique identifier");
		return Data::new(
			Version::Ver0_1,
			&unique_identifier,
			Operation::Communicate(vec![10, 20, 30]),
		)
	}
}
