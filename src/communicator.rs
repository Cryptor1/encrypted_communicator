//! The main module of this crate. Is responsible for handling encrypted
//! communication routines.

mod error;
mod processed_data;

pub use super::data::Uid;

pub use self::error::Error;
pub use self::error::Kind;
pub use self::processed_data::ProcessedData;

use std::cell::RefCell;
use std::collections::HashMap;

use crate::data::Error as DataError;
use crate::data::ErrorKind as DataErrorKind;
use super::data::Data;
use super::data::Operation;
use super::data::ResponseErrorType;
use super::data::Version;
use super::secret::{Aes, CommunicationKey, NegotiationKey, Rsa, RsaKeySize};

/// Represents communication instance. Is the&nbsp;basic struct around which
/// this create is built. Handles following communication routines:
/// * Prepares negotiation data to establish encrypted communication with
/// another `Communicator`.
/// * Handles `Communicator`&#x2011;specific service data to be sent to or
/// received from another `Communicator`.
/// * Manages `CommunicationKey`'s used for encrypted communication between
/// `Communicator` instances.
/// * Encrypts data to be sent&nbsp;/ decrypts received data.
pub struct Communicator {
	/// A unique identifier of this communicator.
	uid: RefCell<Uid>,
	/// Known communication instances. Keys represent a&nbsp;given communicator
	/// unique identifier; values represent keys used to communicate with
	/// a&nbsp;given communication instance.
	known_communicators: RefCell<HashMap<Uid, Box<dyn CommunicationKey>>>,
	/// Tracks communicators (along with negotiation keys used in
	/// an&nbsp;establish request) a&nbsp;connection with which was requested,
	/// but no&nbsp;response has been received yet.
	/// <p><i>Implementation note.</i> Stored negotiation keys must contain
	/// private part in order to be able to decrypt the&nbsp;related received
	/// response.
	outgoing_requests: RefCell<HashMap<Uid, Box<dyn NegotiationKey>>>,
	/// Overwrites default behavior in case of `Communicator` instance receives
	/// `data::Operation::Establish` connection request from an&nbsp;already
	/// known `Communicator` instance.
	///
	/// # Closure signature
	/// ## Parameters
	/// `Uid` &#x2013; Already known connection.
	///
	/// ## Return value
	/// * `true` &ndash; allow to reestablish connection: remove already
	/// defined common encryption key and perform acknowledging from scratch.
	/// * `false` &ndash; deny reestablishing the&nbsp;connection.
	///
	/// # See also
	/// `Communicator::set_establish_behavior()`
	establish_behavior: Option<Box<dyn Fn(&Uid) -> bool>>,
}

impl Communicator {
	/// Creates new `Communicator` instance without known communication
	/// instances.
	/// # Possible errors
	/// * `data::error::kind::Kind::UidGeneration`
	/// # See also
	/// [`new_with_known_communicators()`](struct.Communicator.html#method.new_with_known_communicators)
	pub fn new() -> Result<Self, Error> {
		let uid: Result<Uid, DataError> = Uid::generate_totally_unique();

		if let Err(err) = uid {
			match err.kind() {
				DataErrorKind::UidGeneration => {
					return Err(error::new(Kind::UidGeneration))
				},
				_ => panic!(
					"Internal error: Unexpected error of type `{:?}` has \
						occurred while generating a unique identifier to \
						represent this communicator instance",
					err,
				),
			}
		}

		return Ok(
			Self {
				uid: RefCell::new(Uid::generate_totally_unique().unwrap()),
				known_communicators: RefCell::new(HashMap::new()),
				outgoing_requests: RefCell::new(HashMap::new()),
				establish_behavior: None,
			}
		)
	}


	/// Creates new `Communicator` with known communication instances.
	///
	/// # Parameters
	/// * `uid` &ndash; Unique identifier of this communicator.
	/// * `known_communicators` &ndash; Known communicators (represented by
	/// keys) along with encryption keys (represented by values) used to
	/// communicate with a&nbsp;given communicator.
	///
	/// # See also
	/// [`new()`](struct.Communicator.html#method.new)
	pub fn new_with_known_communicators(
		uid: Uid, known_communicators: HashMap<Uid, Box<dyn CommunicationKey>>) -> Self {

		return Self {
			uid: RefCell::new(uid),
			known_communicators: RefCell::new(known_communicators),
			outgoing_requests: RefCell::new(HashMap::new()),
			establish_behavior: None,
		}
	}

	pub fn uid(&self) -> Uid { self.uid.borrow().clone() }

	pub fn set_uid(&self, uid: Uid) { *self.uid.borrow_mut() = uid; }

	pub fn add_communicator(&self, id: Uid, communication_key: impl CommunicationKey + 'static)
		-> Option<Box<dyn CommunicationKey>> {

		return self.known_communicators.borrow_mut().insert(id, Box::new(communication_key));
	}

	pub fn remove_communicator(&self, id: &Uid) -> Option<Box<dyn CommunicationKey>> {
		return self.known_communicators.borrow_mut().remove(id)
	}

	/// Allows to manage behavior in case of a&nbsp;`Communicator` instance
	/// receives connection request from a&nbsp;`Communicator` instance,
	/// a&nbsp;connection with which has already been established.
	pub fn set_establish_behavior(&mut self, behavior: Option<Box<dyn Fn(&Uid) -> bool>>) {
		self.establish_behavior = behavior;
	}

	/// Performs handling of received data based on its type and purpose.
	/// # Parameters
	/// * `data` &ndash; Data to be processed.
	/// # Possible errors
	/// * `error::kind::Kind::InappropriateData`
	/// * `error::kind::Kind::KeyGenerationFailure`
	/// * `error::kind::Kind::KeyDecryption`
	/// * `error::kind::Kind::AlreadyEstablished`
	/// * `error::kind::Kind::DataDecryption`
	pub fn process_incoming(&self, data: &[u8]) -> Result<ProcessedData, Error> {
		let data = match Data::from_bytes(data) {
			Ok(data) => data,
			Err(_) => return Err(error::new(Kind::InappropriateData)),
		};

		match data.get_operation() {
			Operation::Establish(negotiation_key) => {
				let is_already_established = self.known_communicators.borrow()
					.contains_key(data.get_uid());
				if is_already_established {
					info!(
						"Obtained a request to connect with the already established `{}` \
							communicator",
						data.get_uid(),
					);
				}
				let do_establish = match &self.establish_behavior {
					Some(establish_behavior) if is_already_established => {
						let conclusion = establish_behavior(data.get_uid());
						if conclusion {
							info!(
								"Reestablish connection with the already established `{}` \
									communicator",
								data.get_uid(),
							);
						}
						conclusion
					},
					_ => true,
				};

				if do_establish {
					let communication_key = match Aes::new_random() {
						Ok(key) => key,
						Err(_) => return Err(error::new(Kind::KeyGenerationFailure)),
					};
					let communication_key_encrypted = negotiation_key.encrypt_with_public(
						communication_key.bytes().as_slice());
					let communication_key_encrypted = match communication_key_encrypted {
						Ok(key) => key,
						Err(_) => return Err(error::new(Kind::KeyGenerationFailure)),
					};
					self.known_communicators.borrow_mut()
						.insert(data.get_uid().clone(), Box::new(communication_key));
					let response = Data::new(
						Version::Ver0_1,
						&self.uid.borrow(),
						Operation::Response(Ok(communication_key_encrypted)),
					)
						.convert_to_bytes()
						.expect("Unexpected error while converting response to raw bytes");
					return Ok(ProcessedData::Service(response, self.uid().clone()))
				}
				else {
					let response: Vec<u8> = Data::new(
						Version::Ver0_1,
						&self.uid.borrow(),
						Operation::Response(Err(ResponseErrorType::AlreadyEstablished)),
					)
						.convert_to_bytes()
						.expect("Unexpected error while converting response to raw bytes");
					return Ok(ProcessedData::Service(response, self.uid().clone()))
				}
			},
			Operation::Response(response) => {
				let negotiation_key = self.outgoing_requests.borrow_mut().remove(data.get_uid());
				let negotiation_key = match negotiation_key {
					Some(negotiation_key) => negotiation_key,
					None => {
						info!(
							"Received a response from `{}` communicator request to which has \
								not been sent",
							data.get_uid(),
						);
						return Ok(ProcessedData::None)
					},
				};
				match response {
					Ok(aes_encrypted) => {
						let decryption_result = negotiation_key.decrypt_with_private(
							aes_encrypted.as_slice());
						let communication_key = match decryption_result {
							Ok(communication_key) => communication_key,
							Err(_) => {
								return Err(error::new(Kind::KeyDecryption(data.get_uid().clone())))
							},
						};
						match Aes::from_bytes(communication_key.as_slice()) {
							Ok(aes_key) => {
								self.known_communicators.borrow_mut()
									.insert(data.get_uid().clone(), Box::new(aes_key));
								return Ok(
									ProcessedData::ConnectionEstablished(data.get_uid().clone()))
							},
							Err(_) => {
								return Err(error::new(Kind::KeyDecryption(data.get_uid().clone())))
							},
						};
					},
					Err(err) => {
						match err {
							ResponseErrorType::AlreadyEstablished => {
								return Err(
									error::new(Kind::AlreadyEstablished(data.get_uid().clone())))
							}
						}
					},
				}
			},
			Operation::Communicate(encrypted_data) => {
				match self.known_communicators.borrow().get(data.get_uid()) {
					Some(key) => {
						match key.decrypt(encrypted_data.as_slice()) {
							Ok(decrypted_data) => {
								let result = ProcessedData::Communication(
									decrypted_data, data.get_uid().clone());
								return Ok(result)
							},
							Err(_) => return Err(error::new(Kind::DataDecryption)),
						}
					},
					None => {
						info!(
							"Received communication data from an unknown `{}` communicator",
							data.get_uid(),
						);
						return Ok(ProcessedData::None)
					},
				}
			},
		}
	}

	/// * Encrypts `data_to_encrypt`;
	/// * Prepares auxiliary metadata for the&nbsp;encrypted data.
	///
	/// **Security notice.** One has to be aware that passing large
	/// `data_to_encrypt` results in large memory allocation.
	/// # Parameters
	/// * `uid` &ndash; Unique identifier of communicator to encrypt
	/// `data_to_encrypt` for. A&nbsp;connection with it is expected to be
	/// already established (i.&#x2060;e.&nbsp;a&nbsp;communication key has been
	/// defined for the&nbsp;communicator with `uid`). Otherwise error with
	/// `error::Kind::CommunicationKeyAbsent` will be returned.
	/// # Possible errors
	/// * `error::kind::Kind::CommunicationKeyAbsent`
	/// * `error::kind::Kind::DataEncryption`
	pub fn process_outgoing(&self, uid: &Uid, data_to_encrypt: &[u8]) -> Result<Vec<u8>, Error> {
		let encrypted_data = match self.known_communicators.borrow().get(uid) {
			Some(communication_key) => {
				match communication_key.encrypt(data_to_encrypt) {
					Ok(encrypted_data) => encrypted_data,
					Err(err) => return Err(error::new(Kind::DataEncryption(err))),
				}
			},
			// Covered with `communicator_process_outgoing_unknown_uid()` test
			None => return Err(error::new(Kind::CommunicationKeyAbsent(uid.clone()))),
		};
		let outgoing_data = Data::new(
			Version::Ver0_1, &self.uid(), Operation::Communicate(Vec::from(encrypted_data)));
		// Covered with `communicator_process_outgoing()` and
		// `communicator_process_outgoing_empty_data()` tests
		return Ok(
			outgoing_data.convert_to_bytes()
				// No error is expected here
				.expect("Internal error: Failed to serialize data structure for sending")
		)
	}

	/// Prepares a&nbsp;connection request to `another_communicator`
	/// # Parameters
	/// * `another_communicator` &ndash; communicator a&nbsp;connection with
	/// which is going to be established.
	/// # Return
	/// Raw bytes which represent a&nbsp;connection request.
	/// # Possible errors
	/// * `error::kind::Kind::AlreadyRequested`
	/// * `error::kind::Kind::KeyGenerationFailure`
	pub fn request_connection(&self, another_communicator: &Uid)
		-> Result<Vec<u8>, Error> {

		if self.outgoing_requests.borrow().contains_key(another_communicator) {
			// Covered with `communicator_request_connection_already_requested()`
			// test
			return Err(error::new(Kind::AlreadyRequested))
		}
		let negotiation_key: Rsa = match Rsa::new(RsaKeySize::Rsa1024) {
			Ok(key) => key,
			Err(_) => return Err(error::new(Kind::KeyGenerationFailure)),
		};
		let public_key_part: Rsa = negotiation_key.public_part();
		self.outgoing_requests.borrow_mut()
			.insert(another_communicator.clone(), Box::new(negotiation_key));
		let connection_request: Data = Data::new(
			Version::Ver0_1,
			&self.uid.borrow(),
			Operation::Establish(Box::new(public_key_part)),
		);
		// Covered with `communicator_request_connection()` test
		return Ok(
			connection_request.convert_to_bytes().expect(
				"Unexpected internal error while converting prepared connection request \
					to raw bytes",
			),
		)
	}
}

#[cfg(test)]
mod tests {
	use std::cell::{Ref, RefCell};
	use std::collections::HashMap;
	use std::ops::Deref;
	use crate::communicator::{Communicator, Error, ProcessedData};
	use crate::communicator::error::Kind;
	use crate::data::{Data, Operation, ResponseErrorType, Uid, Version};
	use crate::secret::{Aes, CommunicationKey, NegotiationKey, RsaKeySize, Rsa};

	/// Tests `Communicator::new()` function's happy path.
	#[test]
	fn communicator_new() { Communicator::new().unwrap(); }

	/// Tests `Communicator::new_with_known_communicators()` function's happy
	/// path.
	#[test]
	fn communicator_new_with_known_communicators() {
		let (own_identifier, known_communicators): (Uid, HashMap<Uid, Box<dyn CommunicationKey>>) =
			generate_own_uid_and_known_communicators();
		Communicator::new_with_known_communicators(
			own_identifier,
			known_communicators,
		);
	}

	/// Tests `Communicator::uid()` function's happy path. Ensures obtained
	/// `Uid` equals to the&nbsp;one `Communicator` instance has been created
	/// with.
	#[test]
	fn communicator_get_uid() {
		let expected_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communicator: Communicator = Communicator::new_with_known_communicators(
			expected_identifier.clone(),
			HashMap::new(),
		);
		let actual_identifier = communicator.uid();
		assert_eq!(
			expected_identifier,
			actual_identifier,
			"Obtained unique identifier differs from the one `Communicator` \
				instance has been created with",
		);
	}

	/// Tests `Communicator::set_uid()` function's happy path. Checks that new
	/// unique identifier is returned from `Communicator::uid()` after its
	/// updating.
	#[test]
	fn communicator_set_uid() {
		let communicator: Communicator = Communicator::new().unwrap();
		let new_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		communicator.set_uid(new_uid.clone());
		assert_eq!(
			new_uid,
			communicator.uid(),
			"Unique identifier has not been properly updated",
		);
	}

	/// Tests `Communicator::add_communicator()` function's happy path.
	/// * Adds existing unique identifier.
	/// * Adds nonexistent unique identifier.
	#[test]
	fn communicator_add_communicator() {
		let (own_identifier, known_communicators): (Uid, HashMap<Uid, Box<dyn CommunicationKey>>) =
			generate_own_uid_and_known_communicators();
		let communicator: Communicator = Communicator::new_with_known_communicators(
			own_identifier,
			known_communicators,
		);

		// Add nonexistent entry
		let other_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key_1: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let communication_key_1_copy: Aes =
			Aes::from_bytes(communication_key_1.bytes().as_slice())
				.expect("Failed to create a copy of communication key");
		let add_result: Option<Box<dyn CommunicationKey>> = communicator.add_communicator(
			other_identifier.clone(), communication_key_1);
		assert!(
			add_result.is_none(),
			"Adding nonexistent unique identifier should not result in \
				returning encryption key",
		);

		// Add existing entry
		let communication_key_2: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let add_result: Box<dyn CommunicationKey> =
			communicator.add_communicator(other_identifier, communication_key_2)
				.expect(
					"Adding existing unique identifier should have returned \
						previous encryption key used to communicate with another \
						communicator",
				);
		assert!(
			is_keys_equal(&communication_key_1_copy, add_result.as_ref()),
			"Old communication key, returned as a result of adding new the one, is not correct",
		);
	}

	/// Tests `Communicator::remove_communicator()` function's happy path.
	/// * Removes existing communicator.
	/// * Removes nonexistent communicator.
	#[test]
	fn communicator_remove_communicator() {
		let own_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let communication_key_copy: Aes =
			Aes::from_bytes(communication_key.bytes().as_slice())
				.expect("Failed to create a copy of communication key");
		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		known_communicators.insert(other_identifier.clone(), Box::new(communication_key));
		let communicator: Communicator = Communicator::new_with_known_communicators(
			own_identifier,
			known_communicators,
		);

		// Remove existing communicator
		let communication_key: Box<dyn CommunicationKey> =
			communicator.remove_communicator(&other_identifier)
				.expect(
					"Removing existing communicator's unique identifier is expected \
						to result in encryption key to be returned",
				);
		assert!(
			is_keys_equal(&communication_key_copy, communication_key.as_ref()),
			"Communication key, returned as a result of removing a communicator \
				instance, is incorrect",
		);

		// Remove nonexistent communicator
		let communication_key: Option<Box<dyn CommunicationKey>> = communicator.remove_communicator(
			&Uid::generate_totally_unique().expect("Failed to generate unique identifier"));
		match communication_key {
			None => (),
			Some(_) => {
				panic!(
					"An attempt to remove nonexistent communicator is expected to result in \
						nothing to be returned. Returned a communication key instead",
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Establish` request from an&nbsp;unknown communicator.
	#[test]
	fn communicator_process_incoming_establish_operation() {
		let this_communicator: Communicator = Communicator::new()
			.expect("Failed to create communicator");
		let other_communicator: Communicator = Communicator::new()
			.expect("Failed to create communicator");
		let connection_request: Vec<u8> =
			other_communicator.request_connection(&this_communicator.uid())
				.expect("Failed to generate connection request data");
		let establish_response: ProcessedData =
			this_communicator.process_incoming(connection_request.as_slice())
				.expect("Failed to generate establish confirmation response data");
		match establish_response {
			ProcessedData::Service(data, uid) => {
				other_communicator.process_incoming(data.as_slice())
					.expect("Failed to process establish confirmation response data");
				assert_eq!(
					*this_communicator.uid.borrow(),
					uid,
					"Communicator, which accepted connection and prepared connection-established \
						response, has to provide own unique identifier along with response",
				);
			},
			other_data => {
				panic!(
					"`{:?}` is not expected to be returned as a result of \
						establish-communication request processing from \
						an unknown communicator",
					other_data,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Establish` request from an&nbsp;already known communicator.
	/// Accepts it.
	#[test]
	fn communicator_process_incoming_establish_operation_accept_reestablish() {
		let own_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		known_communicators.insert(other_identifier.clone(), Box::new(communication_key));
		let this_communicator: Communicator = Communicator::new_with_known_communicators(
			own_identifier, known_communicators);
		let other_communicator: Communicator =
			Communicator::new_with_known_communicators(
				other_identifier,
				HashMap::new(),
			);

		let known_communicators: Ref<'_, HashMap<Uid, Box<dyn CommunicationKey>>> =
			this_communicator.known_communicators.borrow();
		let current_communication_key_1: &Box<dyn CommunicationKey> =
			known_communicators.get(&other_communicator.uid())
				.expect(
					"Communicator instance does not contain communication key \
						with another communicator",
				);
		let current_communication_key_1: Aes =
			Aes::from_bytes(current_communication_key_1.as_ref().bytes().as_slice())
				.expect("Failed to generate custom encryption key");
		drop(known_communicators);
		let connection_request: Vec<u8> =
			other_communicator.request_connection(&this_communicator.uid())
				.expect("Failed to generate connection request data");
		let establish_response: ProcessedData =
			this_communicator.process_incoming(connection_request.as_slice())
				.expect("Failed to generate already-established response data");
		match establish_response {
			ProcessedData::Service(data, uid) => {
				assert!(!data.is_empty(), "Already-established response data is empty");
				assert_eq!(
					*this_communicator.uid.borrow(),
					uid,
					"Communicator, which accepted connection reestablishing and prepared \
						corresponding response, has to provide own unique identifier along with \
						response",
				);
			},
			other_data => {
				panic!(
					"`{:?}` is not expected to be returned as a result of \
						establish-communication request processing from a known \
						communicator",
					other_data,
				)
			},
		}
		let known_communicators: Ref<'_, HashMap<Uid, Box<dyn CommunicationKey>>> =
			this_communicator.known_communicators.borrow();
		let current_communication_key_2: &Box<dyn CommunicationKey> =
			known_communicators.get(&other_communicator.uid())
				.expect(
					"Communicator instance does not contain communication key \
						with another communicator",
				);
		let current_communication_key_2: Aes =
			Aes::from_bytes(current_communication_key_2.bytes().as_slice())
				.expect("Failed to generate custom encryption key");
		drop(known_communicators);
		assert_ne!(
			current_communication_key_1,
			current_communication_key_2,
			"Communication key remains the same after re-accepting already \
				established communication",
		);
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Establish` request from an&nbsp;already known communicator.
	/// Rejects it due to establish behavior set with restriction (see
	/// `Communicator::set_establish_behavior()` function).
	#[test]
	fn communicator_process_incoming_establish_operation_decline_reestablish() {
		let own_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		known_communicators.insert(other_identifier.clone(), Box::new(communication_key));
		let mut this_communicator: Communicator = Communicator::new_with_known_communicators(
			own_identifier, known_communicators);
		let other_communicator: Communicator = Communicator::new_with_known_communicators(
			other_identifier, HashMap::new());
		let known_communicators: Ref<'_, HashMap<Uid, Box<dyn CommunicationKey>>> =
			this_communicator.known_communicators.borrow();
		let current_communication_key_1: &Box<dyn CommunicationKey> =
			known_communicators.get(&other_communicator.uid())
				.expect(
					"Communicator instance does not contain communication key \
						with another communicator",
				);
		let current_communication_key_1: Aes =
			Aes::from_bytes(current_communication_key_1.bytes().as_slice())
				.expect("Failed to generate custom encryption key");
		drop(known_communicators);
		let connection_request: Vec<u8> =
			other_communicator.request_connection(&this_communicator.uid())
				.expect("Failed to generate connection request data");
		this_communicator.set_establish_behavior(Some(Box::new(|_| false)));
		let establish_response: ProcessedData =
			this_communicator.process_incoming(connection_request.as_slice())
				.expect("Failed to properly refuse connection request");
		match establish_response {
			ProcessedData::Service(data, uid) => {
				let response_data: Data = Data::from_bytes(data.as_slice())
					.expect("Failed to deserialize raw bytes into `Data` object");
				assert_eq!(
					*this_communicator.uid.borrow(),
					uid,
					"Communicator, which refused connection with already-established \
						reason, has to provide own unique identifier along with \
						response",
				);
				match response_data.get_operation() {
					Operation::Response(response) => {
						match response {
							Err(err) => {
								assert_eq!(
									&ResponseErrorType::AlreadyEstablished,
									err,
									"Communicator, which refused connection \
										request with already-established reason, \
										provided incorrect response error type",
								);
							},
							Ok(success) => {
								panic!(
									"Communicator provided incorrect, `{:?}`, \
										successful response instead of the error \
										one with already-established reason",
									success,
								)
							},
						}
					},
					err => {
						panic!(
							"Communicator provided incorrect, `{:?}`, response \
								as a result of processing connection request, \
								which is expected to be refused with \
								already-established reason",
							err,
						)
					},
				}
			},
			other_error => {
				panic!(
					"Incorrect error type, `{:?}`, has been returned as \
						an already-established response",
					other_error,
				)
			},
		}

		let known_communicators: Ref<'_, HashMap<Uid, Box<dyn CommunicationKey>>> =
			this_communicator.known_communicators.borrow();
		let current_communication_key_2: &Box<dyn CommunicationKey> =
			known_communicators.get(&other_communicator.uid())
				.expect(
					"Communicator instance does not contain communication key \
						with another communicator",
				);
		let current_communication_key_2: Aes =
			Aes::from_bytes(current_communication_key_2.bytes().as_slice())
				.expect("Failed to generate custom encryption key");
		drop(known_communicators);
		assert_eq!(
			current_communication_key_1,
			current_communication_key_2,
			"Communicator, which refused connection request with \
				already-established reason, is expected to retain the same \
				communication key for the another communicator, recurring \
				connection request from which has been obtained",
		);
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Response` receiving from another Communicator,
	/// a&nbsp;communication with which has been requested.
	#[test]
	fn communicator_process_incoming_response_operation() {
		let this_communicator: Communicator = Communicator::new()
			.expect("Failed to create communicator");
		let other_communicator: Communicator = Communicator::new()
			.expect("Failed to create communicator");
		let connection_request: Vec<u8> =
			other_communicator.request_connection(&this_communicator.uid())
				.expect("Failed to generate connection request data");
		let establish_response: ProcessedData =
			this_communicator.process_incoming(connection_request.as_slice())
				.expect("Failed to generate establish confirmation response data");

		let known_communicators: Ref<'_, HashMap<Uid, Box<dyn CommunicationKey>>> =
			this_communicator.known_communicators.borrow();
		let sent_communication_key: &Box<dyn CommunicationKey> =
			known_communicators.get(&other_communicator.uid())
				.expect(
					"Communicator instance does not contain communication key \
						which is expected to be sent to another communicator",
				);
		let sent_communication_key: Aes =
			Aes::from_bytes(sent_communication_key.bytes().as_slice())
				.expect("Failed to generate custom encryption key");
		drop(known_communicators);

		let received_response: ProcessedData;
		match establish_response {
			ProcessedData::Service(data, _) => {
				received_response = other_communicator.process_incoming(data.as_slice())
					.expect("Failed to process establish confirmation response data");
			},
			other_data => {
				panic!(
					"`{:?}` is not expected to be returned as a result of \
						establish-communication request processing from \
						an unknown communicator",
					other_data,
				)
			},
		}
		match received_response {
			ProcessedData::ConnectionEstablished(uid) => {
				assert_eq!(
					this_communicator.uid.borrow().deref(),
					&uid,
					"Unique identifier of the Communicator, which accepted \
						connection request, is expected to be returned as \
						a result of response processing",
				);
			},
			other_processed_data => {
				panic!(
					"Established-connection response processing resulted in \
						incorrect return type, `{:?}`",
					other_processed_data,
				)
			},
		}

		let known_communicators: Ref<'_, HashMap<Uid, Box<dyn CommunicationKey>>> =
			other_communicator.known_communicators.borrow();
		let received_communication_key: &Box<dyn CommunicationKey> =
			known_communicators.get(&this_communicator.uid())
				.expect(
					"Communicator instance does not contain communication key \
						which is expected to be received from another communicator",
				);
		let received_communication_key: Aes =
			Aes::from_bytes(received_communication_key.bytes().as_slice())
				.expect("Failed to generate custom encryption key");
		drop(known_communicators);
		assert_eq!(
			sent_communication_key,
			received_communication_key,
			"Communication key sent to another communicator does not match \
				the one actually received",
		);
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Response` receiving from an&nbsp;unknown Communicator.
	#[test]
	fn communicator_process_incoming_response_operation_unknown_communicator() {
		let this_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let other_communicator_1: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let other_communicator_2: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let connection_request: Vec<u8> =
			other_communicator_1.request_connection(&other_communicator_2.uid.borrow())
				.expect("Failed to prepare a connection request");
		let connection_response: ProcessedData =
			other_communicator_2.process_incoming(connection_request.as_slice())
				.expect("Failed to prepare response for a connection request");
		let connection_response: Vec<u8> = match connection_response {
			ProcessedData::Service(data, _) => data,
			incorrect_response_data => {
				panic!(
					"Incorrect `{:?}` data has been generated as a result of \
						connection request processing",
					incorrect_response_data,
				)
			},
		};
		let processed_response: ProcessedData =
			this_communicator.process_incoming(connection_response.as_slice())
				.expect("Failed to process connection response from an unknown communicator");
		match processed_response {
			ProcessedData::None => (),
			incorrectly_processed_request => {
				panic!(
					"Incorrect `{:?}` data has been generated as a result of \
						processing a connection response from an unknown \
						communicator",
					incorrectly_processed_request,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's error path. Checks
	/// `Operation::Response` receiving with already&#x2011;established response.
	#[test]
	fn communicator_process_incoming_response_operation_already_established() {
		let this_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let mut other_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		known_communicators.insert(
			this_communicator.uid.borrow().clone(),
			Box::new(Aes::new_random().expect("Failed to generate communication key")),
		);
		other_communicator.known_communicators.replace(known_communicators);
		other_communicator.establish_behavior = Some(Box::new(|_| false));
		let connection_request: Vec<u8> =
			this_communicator.request_connection(&other_communicator.uid.borrow())
				.expect("Failed to prepare connection request");
		let connection_response: ProcessedData =
			other_communicator.process_incoming(connection_request.as_slice())
				.expect(
					"Failed to properly process connection request and generate \
						response",
				);
		let connection_response: Vec<u8> = match connection_response {
			ProcessedData::Service(response_data, _) => response_data,
			incorrect_response_data => {
				panic!(
					"Incorrect `{:?}` data has been generated as a result of \
						connection request processing",
					incorrect_response_data,
				)
			},
		};
		let processed_response: Error =
			this_communicator.process_incoming(connection_response.as_slice())
				.expect_err(
					"Communicator has improperly processed refused-communication \
						response",
				);
		match processed_response.kind() {
			Kind::AlreadyEstablished(_) => (),
			incorrectly_processed_response => {
				panic!(
					"Communicator has improperly processed refused-communication \
						response with `{:?}`",
					incorrectly_processed_response,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Communicate` operation processing.
	#[test]
	fn communicator_process_incoming_communicate_operation() {
		let this_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let other_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		this_communicator.add_communicator(
			other_communicator.uid.borrow().clone(),
			Aes::from_bytes(communication_key.bytes().as_slice())
				.expect("Failed to generate communication key copy"),
		);
		other_communicator.add_communicator(
			this_communicator.uid.borrow().clone(),
			communication_key,
		);
		let sent_message: &str = "Communication message";
		let data_to_send: Vec<u8> =
			other_communicator.process_outgoing(
				&this_communicator.uid.borrow().clone(),
				sent_message.as_bytes(),
			)
				.expect("Failed to prepare encrypted data to send");
		let received_data: ProcessedData =
			this_communicator.process_incoming(data_to_send.as_slice())
				.expect("Failed to process received data");
		match received_data {
			ProcessedData::Communication(data, uid) => {
				let received_message: &str =
					&String::from_utf8_lossy(data.as_slice()).into_owned();
				assert_eq!(
					sent_message,
					received_message,
					"Sent data was not get properly decrypted",
				);
				assert_eq!(
					*other_communicator.uid.borrow(),
					uid,
					"Communicator, which prepared communication data for sending, has to provide \
						own unique identifier along with encrypted data",
				);
			},
			incorrect_processing_result => {
				panic!(
					"Received communication data has not been properly processed. \
						`{:?}` has been returned as a result of such processing",
					incorrect_processing_result,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's happy path. Checks
	/// `Operation::Communicate` receiving from an&nbsp;unknown communicator.
	#[test]
	fn communicator_process_incoming_communicate_operation_from_unknown() {
		let this_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let unknown_communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		unknown_communicator.known_communicators.borrow_mut()
			.insert(this_communicator.uid.borrow().clone(), Box::new(communication_key));
		let communication_data: Vec<u8> = unknown_communicator.process_outgoing(
			&this_communicator.uid.borrow().clone(),
			vec![10, 20, 30].as_slice(),
		)
			.expect("Failed to prepare communication data to send");
		let processing_result: ProcessedData =
			this_communicator.process_incoming(communication_data.as_slice())
				.expect(
					"Failed to properly process data received from unknown source",
				);
		match processing_result {
			ProcessedData::None => (),
			incorrect_processing_result => {
				panic!(
					"Communicator instance improperly processed data received \
						from unknown source. Unexpected processed data, `{:?}`, \
						has been returned",
					incorrect_processing_result,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's error path. Checks
	/// incorrectly encrypted data receiving from a&nbsp;known communicator.
	#[test]
	fn communicator_process_incoming_communicate_operation_decryption_error() {
		let this_communicator_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_communicator_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		known_communicators.insert(other_communicator_uid.clone(), Box::new(communication_key));
		let this_communicator: Communicator = Communicator::new_with_known_communicators(
			this_communicator_uid, known_communicators);
		let communication_data: Vec<u8> =
			Data::new(
				Version::Ver0_1,
				&other_communicator_uid,
				Operation::Communicate(vec![10, 20, 30]),
			)
				.convert_to_bytes()
				.expect(
					"Failed to convert prepared communication data structure to raw bytes",
				);
		let processing_error: Error =
			this_communicator.process_incoming(communication_data.as_slice())
				.expect_err(
					"Communicator has processed incorrectly encrypted communication \
						data as the correct instead",
				);
		match processing_error.kind() {
			Kind::DataDecryption => (),
			incorrect_error => {
				panic!(
					"Communicator has returned incorrect, `{:?}`, error",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's error path. Checks
	/// incorrectly structured data processing.
	#[test]
	fn communicator_process_incoming_inappropriate_data() {
		let processing_error: Error = Communicator::new()
			.expect("Failed to instantiate communicator")
			.process_incoming(vec![10, 20, 30].as_slice())
			.expect_err(
				"Communicator has processed inappropriate data as \
					the appropriate instead",
			);
		match processing_error.kind() {
			Kind::InappropriateData => (),
			incorrect_error => {
				panic!(
					"Communicator has returned incorrect, `{:?}`, error as \
						the result of incorrectly structured data processing",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's error path. Checks
	/// the&nbsp;case when communicator receives improperly encrypted
	/// communication key as a&nbsp;response from another communicator.
	#[test]
	fn communicator_process_incoming_response_operation_decryption_fail_1() {
		let communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let other_communicator_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		communicator.outgoing_requests.borrow_mut().insert(
			other_communicator_uid.clone(),
			Box::new(Rsa::new(RsaKeySize::Rsa1024).expect("Failed to generate negotiation key")),
		);

		let response_data: Vec<u8> = Data::new(
				Version::Ver0_1,
				&other_communicator_uid,
				Operation::Response(Ok(vec![10, 20, 30])),
			)
			.convert_to_bytes()
			.expect("Failed to convert prepared response data structure into raw bytes");
		let processing_error: Error = communicator.process_incoming(response_data.as_slice())
			.expect_err(
				"Communicator has processed incorrectly encrypted communication \
					key as a correct one",
			);
		match processing_error.kind() {
			Kind::KeyDecryption(actual_uid) => {
				assert_eq!(
					&other_communicator_uid,
					actual_uid,
					"Communicator has returned incorrect unique identifier which \
						is expected to denote other communicator from which \
						a data to process has been obtained",
				);
			},
			incorrect_error => {
				panic!(
					"Communicator has returned incorrect, {:?}, error as \
						the result of processing incorrectly encrypted communication \
						key, received from another communicator",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Communicator::process_incoming()` function's error path. Checks
	/// the&nbsp;case when communicator receives properly encrypted data as
	/// a&nbsp;response for a&nbsp;communication request. However
	/// the&nbsp;encrypted data does not&nbsp;represent an&nbsp;applicable
	/// communication key.
	#[test]
	fn communicator_process_incoming_response_operation_decryption_fail_2() {
		let communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let other_communicator_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let request_key: Rsa = Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to generate a key to be sent with connection request");
		communicator.outgoing_requests.borrow_mut().insert(
			other_communicator_uid.clone(), Box::new(request_key));

		let outgoing_requests: Ref<'_, HashMap<Uid, Box<dyn NegotiationKey>>> =
			communicator.outgoing_requests.borrow();
		let request_key: &Box<dyn NegotiationKey> = outgoing_requests.get(&other_communicator_uid)
			.expect(
				"Communicator does not contain communication request key in outgoing requests list",
			);
		let incorrect_communication_key: Vec<u8> =
			request_key.encrypt_with_public(vec![10, 20, 30].as_slice())
				.expect(
					"Failed to encrypt data using previously generated \
						`secret::negotiation_key::NegotiationKey`",
				);
		drop(outgoing_requests);
		let response_data: Vec<u8> = Data::new(
			Version::Ver0_1,
			&other_communicator_uid,
			Operation::Response(Ok(incorrect_communication_key)),
		)
			.convert_to_bytes()
			.expect("Failed to convert prepared response data structure into raw bytes");
		let processing_error: Error = communicator.process_incoming(response_data.as_slice())
			.expect_err("Communicator has processed encrypted data as a correct communication key");
		match processing_error.kind() {
			Kind::KeyDecryption(actual_uid) => {
				assert_eq!(
					&other_communicator_uid,
					actual_uid,
					"Communicator has returned incorrect unique identifier which is expected to \
						denote other communicator from which a data to process has been obtained",
				);
			},
			incorrect_error => {
				panic!(
					"Communicator has returned incorrect, {:?}, error as the result of processing \
						incorrect communication key, received from another communicator",
					incorrect_error,
				)
			},
		}
	}

	/// Tests `Communicator::process_outgoing()` function's error path. Checks
	/// the&nbsp;case when the&nbsp;mentioned function is requested to encrypt
	/// a&nbsp;data for an&nbsp;unknown instance of another communicator.
	#[test]
	fn communicator_process_outgoing_unknown_uid() {
		let communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		let unknown_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let processing_error: Error = communicator.process_outgoing(
			&unknown_identifier,
			vec![10, 20, 30].as_slice(),
		)
			.expect_err(
				"Communicator has encrypted data for an unknown instance of another \
					communicator",
			);
		match processing_error.kind() {
			Kind::CommunicationKeyAbsent(actual_identifier) => {
				assert_eq!(
					&unknown_identifier,
					actual_identifier,
					"Communicator has returned incorrect identifier which denotes \
						another communicator for which data was expected to be encrypted",
				);
			},
			incorrect_processing_error => {
				panic!(
					"Incorrect error, `{:?}`, has been returned as a result of data \
						encrypting for an unknown communicator",
					incorrect_processing_error,
				)
			},
		}
	}

	/// Tests `Communicator::process_outgoing()` function's happy path. Passes
	/// a&nbsp;vector with data for encryption and communication message
	/// preparation.
	#[test]
	fn communicator_process_outgoing() {
		let this_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let this_communicator: Communicator = create_communicator_with_known_uids(
			&this_uid, &other_uid, &communication_key);
		this_communicator.process_outgoing(&other_uid, vec![10, 20, 30].as_slice())
			.expect("Failed to prepare outgoing data for another communicator");
	}

	/// Tests `Communicator::process_outgoing()` function's happy path. Checks
	/// empty communication data passing.
	#[test]
	fn communicator_process_outgoing_empty_data() {
		let this_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let this_communicator: Communicator = create_communicator_with_known_uids(
			&this_uid, &other_uid, &communication_key);
		let other_communicator: Communicator = create_communicator_with_known_uids(
			&other_uid, &this_uid, &communication_key);
		let communication_data: Vec<u8> =
			this_communicator.process_outgoing(&other_uid, vec![].as_slice())
				.expect("Failed to prepare outgoing data for another communicator");
		let processed_data: ProcessedData =
			other_communicator.process_incoming(communication_data.as_slice())
				.expect("Failed to process received data from another communicator");
		match processed_data {
			ProcessedData::Communication(data, uid) => {
				assert!(
					data.is_empty(),
					"Received data from another communicator is expected to be empty",
				);
				assert_eq!(
					this_uid,
					uid,
					"Communicator, which prepared communication data for sending, has to provide \
						own unique identifier along with encrypted data",
				);
			},
			incorrectly_processed_data => {
				panic!(
					"Communicator has produced incorrect result, `{:?}`, while processing \
						communication data from another communicator",
					incorrectly_processed_data,
				)
			},
		}
	}

	/// Tests `Communicator::set_establish_behavior()` function's happy path.
	#[test]
	fn communicator_set_establish_behavior() {
		let mut communicator: Communicator = Communicator::new()
			.expect("Failed to instantiate communicator");
		communicator.set_establish_behavior(Some(Box::new(|_| false)));
	}

	/// Tests `Communicator::request_connection()` function's happy path.
	#[test]
	fn communicator_request_connection() {
		let own_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communicator: Communicator = Communicator {
			uid: RefCell::new(own_uid),
			known_communicators: RefCell::new(HashMap::new()),
			outgoing_requests: RefCell::new(HashMap::new()),
			establish_behavior: None,
		};
		communicator.request_connection(&other_uid)
			.expect("Failed to prepare connection request");
	}

	/// Tests `Communicator::request_connection()` function's error path. Checks
	/// behavior when requesting a&nbsp;connection with another communicator,
	/// request for which has been already created, but no&nbsp;response has
	/// been received yet.
	#[test]
	fn communicator_request_connection_already_requested() {
		let own_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_uid: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let private_key: Rsa = Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to generate key for the connection request");
		let mut outgoing_requests: HashMap<Uid, Box<dyn NegotiationKey>> = HashMap::new();
		outgoing_requests.insert(other_uid.clone(), Box::new(private_key));
		let communicator: Communicator = Communicator {
			uid: RefCell::new(own_uid),
			known_communicators: RefCell::new(HashMap::new()),
			outgoing_requests: RefCell::new(outgoing_requests),
			establish_behavior: None,
		};
		let request_error: Error = communicator.request_connection(&other_uid)
			.expect_err(
				"Communicator has prepared connection request for the unique identifier, \
					a connection request with which has been already created"
			);
		match request_error.kind() {
			Kind::AlreadyRequested => (),
			incorrect_request_error => {
				panic!(
					"Communicator has returned incorrect, `{:?}`, error as a result of \
						processing a connection request for the unique identifier, \
						a connection request with which has been already created",
					incorrect_request_error,
				)
			},
		}
	}

	/// Auxiliary which generates initialization data for
	/// `Communicator::new_with_known_communicators()`: own unique identifier
	/// and known communicators.
	fn generate_own_uid_and_known_communicators()
		-> (Uid, HashMap<Uid, Box<dyn CommunicationKey>>) {

		let own_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let other_identifier: Uid = Uid::generate_totally_unique()
			.expect("Failed to generate unique identifier");
		let communication_key: Aes = Aes::new_random()
			.expect("Failed to generate communication key");
		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		known_communicators.insert(other_identifier, Box::new(communication_key));
		return (own_identifier, known_communicators)
	}

	/// Instantiates and returns communicator which has one known connection.
	/// # Params
	/// &#x2022; `own_uid`: Unique identifier of a&nbsp;communicator to return.
	///
	/// &#x2022; `known_uid`: Unique identifier of communicator
	/// a&nbsp;communication with which is perceived as established.
	///
	/// &#x2022; `communication_key`: Used to encrypt/decrypt
	/// data&#x2011;to&#x2011;send between returned and its known communicator.
	fn create_communicator_with_known_uids(
		own_uid: &Uid, known_uid: &Uid, communication_key: &Aes) -> Communicator {

		let mut known_communicators: HashMap<Uid, Box<dyn CommunicationKey>> = HashMap::new();
		let communication_key: Aes = Aes::from_bytes(communication_key.bytes().as_slice())
			.expect("Failed to generate communication key's copy");
		known_communicators.insert(known_uid.clone(), Box::new(communication_key));
		let known_communicators: RefCell<HashMap<Uid, Box<dyn CommunicationKey>>> =
			RefCell::new(known_communicators);
		return Communicator {
			uid: RefCell::new(own_uid.clone()),
			known_communicators,
			outgoing_requests: RefCell::new(HashMap::new()),
			establish_behavior: None,
		}
	}

	fn is_keys_equal(
		communication_key_1: &dyn CommunicationKey, communication_key_2: &dyn CommunicationKey,
	) -> bool {
		let name_1: String = communication_key_1.name();
		let name_2: String = communication_key_2.name();
		if name_1 == name_2 {
			let bytes_1: Vec<u8> = communication_key_1.bytes();
			let bytes_2: Vec<u8> = communication_key_2.bytes();
			return bytes_1 == bytes_2;
		}
		return false
	}
}
