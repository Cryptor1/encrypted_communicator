mod operation_error;
mod response_error;

pub use self::operation_error::ErrorKind;
pub use self::operation_error::OperationError;
pub use self::response_error::define_error_type_as_string;
pub use self::response_error::ResponseErrorType;

use crate::secret::{NegotiationKey, Rsa};
use std::fmt::{Debug, Formatter, Error};

/// Operation being performed in a given communication session.
pub enum Operation {
	/// Establish new connection.
	/// # Parameters
	/// * `Box<dyn NegotiationKey>` &ndash; Public part of asymmetric key used
	/// for a&nbsp;common communication secret instantiating.
	Establish(Box<dyn NegotiationKey>),
	/// Response to a&nbsp;request/data.
	/// # Parameters
	/// * `Result<Vec<u8>, ResponseErrorType>` &ndash; Service data
	/// (e.&#x2060;g.&nbsp;encrypted `CommunicationKey`) or an&nbsp;error.
	Response(Result<Vec<u8>, ResponseErrorType>),
	/// Communication operation, such as message sending.
	/// # Parameters
	/// * `Vec<u8>` &ndash; Data which should be encrypted/decrypted.
	Communicate(Vec<u8>),
}

impl Debug for Operation {
	fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
		return match self {
			// Covered with `debug_fmt_for_operation_establish` test
			Operation::Establish(negotiation_key) => {
				let mut tuple_formatter = f.debug_tuple("Operation::Establish");
				if negotiation_key.has_public() {
					tuple_formatter.field(&negotiation_key.public_part());
				} else {
					// Since `Operation::Establish` is intended to carry public
					// key part, log enum-misusing error. Such circumstances
					// must not be possible in whole `encrypted_communicator`
					// crate
					error!(
						"No public part is present in an instance of `NegotiationKey`. This is \
							internal, `encrypted_communicator` crate, implementation error. \
							Further processing may panic",
					);
					tuple_formatter.field(&format_args!("[No public key present]"));
				}
				tuple_formatter.finish()
			},
			Operation::Response(result) => {
				// Covered with `debug_fmt_for_operation_response_ok` and
				// `debug_fmt_for_operation_response_err` tests
				f.debug_tuple("Operation::Response").field(result).finish()
			},
			Operation::Communicate(data) => {
				// Covered with `debug_fmt_for_operation_communicate` test
				f.debug_tuple("Operation::Communicate").field(data).finish()
			},
		}
	}
}

/// Determines enum equivalent of an&nbsp;operation to perform at
/// a&nbsp;given communication session.
///
/// _Note._ This method is intended to process incoming operations only
/// (i.&#x2060;e.&nbsp;those ones received from another communicators).
/// # Parameters
/// * `operation` &ndash; Operation type to perform at a&nbsp;given
/// communication session.
/// * `data` &ndash; The content data related to `operation`.
/// # Possible errors
/// * `data::operation::operation_error::kind::ErrorKind::IncorrectEstablishData`
/// * `data::operation::operation_error::kind::ErrorKind::UndefinedOperation`
/// # See also
/// * `data::Data`
pub fn define_operation(operation: &str, data: &[u8]) -> Result<Operation, OperationError> {
	return match operation {
		"establish" => {
			let negotiation_key = Rsa::new_public_from_pem(data);
			match negotiation_key {
				Ok(key) => Ok(Operation::Establish(Box::new(key))),
				Err(_) => Err(operation_error::new(ErrorKind::IncorrectEstablishData)),
			}
		},
		"response" => {
			let error_type = response_error::define_error_type(&String::from_utf8_lossy(data));
			if let Ok(response_error) = error_type {
				return Ok(Operation::Response(Err(response_error)))
			}
			Ok(Operation::Response(Ok(data.to_vec())))
		},
		"communicate" => Ok(Operation::Communicate(data.to_vec())),
		_ => Err(operation_error::new(ErrorKind::UndefinedOperation)),
	}
}

/// Determines string equivalent of an&nbsp;operation to perform at a&nbsp;given
/// communication session.
pub fn define_operation_as_string(operation: &Operation) -> String {
	return match operation {
		&Operation::Establish(_) => "establish".to_owned(),
		&Operation::Response(_) => "response".to_owned(),
		&Operation::Communicate(_) => "communicate".to_owned(),
	}
}

#[cfg(test)]
mod tests {
	use crate::data::{operation, Operation, ResponseErrorType, OperationError};
	use crate::data::operation::operation_error::ErrorKind;
	use crate::secret::{Aes, CommunicationKey, NegotiationKey, Rsa, RsaKeySize};

	/// Tests `Debug::fmt()` implementation for `Operation`.
	/// `Operation::Establish` debug output checked.
	#[test]
	fn debug_fmt_for_operation_establish() {
		let negotiation_key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key");
		let expected_public_part = NegotiationKey::public_part(&negotiation_key);
		let establish_operation = Operation::Establish(Box::new(negotiation_key));
		assert_eq!(
			format!("Operation::Establish({:?})", expected_public_part),
			format!("{:?}", establish_operation),
			"Incorrect debug info is printed for `Operation::Establish` enum",
		)
	}

	/// Tests `Debug::fmt()` implementation for `Operation`.
	/// `Operation::Response` debug info with `Ok` result is checked.
	#[test]
	fn debug_fmt_for_operation_response_ok() {
		let aes_key = Aes::new_random().expect("Failed to instantiate AES key");
		let rsa_key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key");
		let encrypted_data = rsa_key.encrypt_with_public(&aes_key.bytes())
			.expect("Failed to encrypt AES key using public part of RSA key");
		let encrypted_data_copy = encrypted_data.clone();
		let operation_response = Operation::Response(Ok(encrypted_data));
		assert_eq!(
			format!("Operation::Response(Ok({:?}))", encrypted_data_copy),
			format!("{:?}", operation_response),
			"Incorrect debug info is printed for `Operation::Response` enum with `Ok` result",
		);
	}

	/// Tests `Debug::fmt()` implementation for `Operation`.
	/// `Operation::Response` debug info with `Err` result is checked.
	#[test]
	fn debug_fmt_for_operation_response_err() {
		let expected_debug_output = format!(
			"Operation::Response({:?})",
			Err::<Vec<u8>, ResponseErrorType>(ResponseErrorType::AlreadyEstablished),
		);
		assert_eq!(
			expected_debug_output,
			format!("{:?}", Operation::Response(Err(ResponseErrorType::AlreadyEstablished))),
			"Incorrect debug info is printed for `Operation::Response` enum with `Err` result",
		);
	}

	/// Tests `Debug::fmt()` implementation for `Operation`.
	/// `Operation::Communicate` debug output is checked.
	#[test]
	fn debug_fmt_for_operation_communicate() {
		let communication_data = vec![10, 20, 30];
		assert_eq!(
			format!("Operation::Communicate({:?})", communication_data),
			format!("{:?}", Operation::Communicate(communication_data)),
			"Incorrect debug info is printed for `Operation::Response` enum",
		);
	}

	/// Tests `operation::define_operation()` function's happy path.
	/// The&nbsp;method tests a&nbsp;case where `"establish"` is passed as
	/// `operation` argument.
	#[test]
	fn operation_define_operation_establish() {
		let serialized_public_part_original: Vec<u8> = create_key_public_part().public_part();
		let establish_operation: Operation =
			operation::define_operation("establish", &serialized_public_part_original)
				.expect(
					"Should have generated `Operation::Establish` operation with \
						public part of asymmetric key",
				);
		let serialized_public_part_derived: Vec<u8> =
			if let Operation::Establish(negotiation_key) = establish_operation {
				negotiation_key.public_part()
			} else {
				panic!(
					"Generated operation is expected to be `Operation::Establish`. Found `{:?}` \
						instead",
					establish_operation,
				)
			};
		assert_eq!(
			serialized_public_part_original,
			serialized_public_part_derived,
			"Original serialized key is expected to be equal to the derived one",
		);
	}

	/// Tests `operation::define_operation()` function's happy path.
	/// The&nbsp;method tests a&nbsp;case where `"response"` is passed as
	/// `operation` argument.
	#[test]
	fn operation_define_operation_response() {
		let response_literal: &str = "response";

		// Check response which denotes error
		let already_established_literal: &[u8] = "already established".as_bytes();
		let calculated_operation: Operation = operation
			::define_operation(response_literal, already_established_literal)
			.expect(
				"Should have generated `Operation::Response` operation with \
					a response which denotes already-established error",
			);
		if let Operation::Response(response) = calculated_operation {
			match response {
				Err(incorrect_establish_data) => {
					assert_eq!(
						ResponseErrorType::AlreadyEstablished,
						incorrect_establish_data,
						"Should have generated response with \
							already-established message",
					);
				},
				actual_value => {
					panic!(
						"Should have generated response which denotes \
							already-established error. Generated `{:?}` instead",
						actual_value,
					)
				},
			}
		}
		else {
			panic!(
				"Should have generated `Operation::Response` type. Generated \
					`{:?}` instead",
				calculated_operation,
			)
		}

		// Check response which denotes arbitrary response data
		let dummy_response_data: &[u8] = "dummy response data".as_bytes();
		let calculated_operation: Operation = operation
			::define_operation(response_literal, dummy_response_data)
			.expect(
				"Should have generated `Operation::Response` operation with \
					an arbitrary response data",
			);
		if let Operation::Response(response) = calculated_operation {
			match response {
				Ok(binary_data) => {
					assert_eq!(
						dummy_response_data,
						binary_data.as_slice(),
						"Should have generated response with original data",
					);
				},
				actual_value => {
					panic!(
						"Should have generated response which denotes response \
							arbitrary data. Generated `{:?}` instead",
						actual_value,
					)
				}
			}
		}
		else {
			panic!(
				"Should have generated `Operation::Response` type. Generated \
					`{:?}` instead",
				calculated_operation,
			)
		}
	}

	/// Tests `operation::define_operation()` function's happy path.
	/// The&nbsp;method tests a&nbsp;case where `"communicate"` is passed as
	/// `operation` argument.
	#[test]
	fn operation_define_operation_communicate() {
		let communicate_literal: &str = "communicate";
		let communication_data_original: &[u8] = "Communication data".as_bytes();
		let calculated_operation: Operation = operation
			::define_operation(communicate_literal, communication_data_original)
			.expect("Should have generated `Operation` object");
		if let Operation::Communicate(communication_data) = calculated_operation {
			assert_eq!(
				communication_data_original,
				communication_data.as_slice(),
				"Original communication data should be equal to the one \
					obtained as a result of calculation",
			);
		} else {
			panic!(
				"Should have generated `Operation::Communicate`. Generated \
					`{:?}` instead",
			)
		}
	}

	/// Tests `operation::define_operation()` function. Passes inappropriate
	/// `operation` argument.
	#[test]
	fn operation_define_operation_inappropriate_operation() {
		let dummy_operation_literal: &str = "dummy operation";
		let operation_data: &[u8] = &[];
		let error_operation: OperationError = operation
			::define_operation(dummy_operation_literal, operation_data)
			.expect_err("Should have returned `OperationError` object");
		let error_operation_kind: ErrorKind = error_operation.kind();
		assert_eq!(
			ErrorKind::UndefinedOperation,
			error_operation_kind,
			"Should have returned error which denotes undefined operation",
		);
	}

	/// Tests `operation::define_operation()` function. Passes inappropriate
	/// `data` argument for _establish_ operation.
	#[test]
	fn operation_define_operation_incorrect_data_for_establish_operation() {
		let establish_operation_literal: &str = "establish";
		let incorrect_key: &[u8] = "incorrect key".as_bytes();
		let error_operation: OperationError =
			operation::define_operation(establish_operation_literal, incorrect_key)
				.expect_err("Should have returned `OperationError` object");
		assert_eq!(
			ErrorKind::IncorrectEstablishData,
			error_operation.kind(),
			"Should have returned error which denotes incorrect data for `establish` request",
		);
	}

	/// Tests `operation::define_operation_as_string()` function's happy path.
	#[test]
	fn operation_define_operation_as_string() {
		// Check `establish` operation
		let public_part: Box<dyn NegotiationKey> = Box::new(create_key_public_part());
		let establish_operation: Operation = Operation::Establish(public_part);
		let establish_operation_literal: String =
			operation::define_operation_as_string(&establish_operation);
		assert_eq!(
			"establish",
			establish_operation_literal,
			"Should return literal for `{:?}` operation",
			establish_operation,
		);

		// Check `response` operation
		let response_operation: Operation = Operation::Response(Ok(vec![10, 20, 30]));
		let response_operation_literal: String =
			operation::define_operation_as_string(&response_operation);
		assert_eq!(
			"response",
			response_operation_literal,
			"Should return literal for `{:?}` operation",
			response_operation
		);

		// Check `communicate` operation
		let communicate_operation: Operation = Operation::Communicate(vec![10, 20, 30]);
		let communicate_operation_literal: String =
			operation::define_operation_as_string(&communicate_operation);
		assert_eq!(
			"communicate",
			communicate_operation_literal,
			"Should return literal for `{:?}` operation",
			communicate_operation
		);
	}

	/// Generates and returns a&nbsp;public part of an&nbsp;asymmetric key.
	fn create_key_public_part() -> impl NegotiationKey {
		return Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to instantiate `NegotiationKey` instance")
			.public_part()
	}
}
