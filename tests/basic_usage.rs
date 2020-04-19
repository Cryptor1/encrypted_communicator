extern crate encrypted_communicator;

use encrypted_communicator::communicator::Communicator;
use encrypted_communicator::communicator::ProcessedData;

/// Checks basic usage of the&nbsp;crate:
/// 1. Initializes connection between communicators
/// 1. One communicator encrypts data
/// 1. Another communicator decrypts obtained encrypted data
#[test]
fn test_basic_usage() {
	let this_communicator: Communicator = Communicator::new().unwrap();
	let other_communicator: Communicator = Communicator::new().unwrap();

	let connection_request: Vec<u8> = this_communicator
		.request_connection(&other_communicator.uid()).unwrap();
	let other_communicator_response: ProcessedData = other_communicator
		.process_incoming(&connection_request).unwrap();

	match other_communicator_response {
		ProcessedData::Service(service_data, _) => {
			this_communicator.process_incoming(&service_data).unwrap();
		},
		err => panic!("Unexpected processed data, `{:?}`, has been encountered", err),
	}

	let data_to_encrypt: &str = "Some data to encrypt";

	let encrypted_data_to_send: Vec<u8> = this_communicator
		.process_outgoing(&other_communicator.uid(), data_to_encrypt.as_bytes())
		.unwrap();

	let received_data: ProcessedData = other_communicator.process_incoming(&encrypted_data_to_send)
		.unwrap();

	match received_data {
		ProcessedData::Communication(decrypted_data, _) => {
			assert_eq!(
				unsafe { String::from_utf8_unchecked(decrypted_data) },
				data_to_encrypt,
				"Decrypted data does not match initially encrypted one",
			);
		},
		err => panic!("Unexpected processed data, `{:?}`, has been encountered", err),
	}
}
