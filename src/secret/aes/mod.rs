use crypto::aes;
use crypto::aes::KeySize;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::BufferResult;
use crypto::buffer::ReadBuffer;
use crypto::buffer::RefReadBuffer;
use crypto::buffer::RefWriteBuffer;
use crypto::buffer::WriteBuffer;
use crypto::symmetriccipher::{Encryptor, SymmetricCipherError};
use rand::OsRng;
use rand::Rng;

use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;

use super::error;
use super::error::Error;
use super::error::ErrorKind;
use crate::secret::CommunicationKey;

/// Initialization vector (IV) size in bytes
const IV_SIZE: usize = 16;
const BUFFER_SIZE: usize = 4096;

/// Represents AES encryption key.
pub struct Aes {
	/// Stored key size.
	size: KeySize,
	/// A 32-bytes key.
	key: Vec<u8>,
}

impl Aes {
	// Covered with `aes_key_type()` test
	pub fn key_type() -> String { "AES".to_string() }

	/// Generates random 256&#x2011;bit AES key.
	/// # Possible errors
	/// * `secret::error::error_kind::ErrorKind::GenerationBlocked`
	pub fn new_random() -> Result<Self, Error> {
		let size: KeySize = KeySize::KeySize256;
		let mut key: Vec<u8> = vec![0; Self::define_size_in_bytes(&size) as usize];
		match OsRng::new() {
			Ok(mut random_generator) => random_generator.fill_bytes(&mut key),
			Err(_) => return Err(error::new(ErrorKind::GenerationBlocked)),
		}
		// Covered with `aes_new_random()` test
		return Ok(Self { size, key: key.to_vec() })
	}

	/// Generates custom AES key.
	/// # Parameters
	/// * `key` &ndash; bytes sequence which represents the&nbsp;encryption
	/// key.<br/>
	/// **Important.** This parameter must be one of possible sizes defined by
	/// `KeySize` enum. An&nbsp;expected size for a&nbsp;given enum constant can
	/// be checked by `define_size_in_bytes()` function.
	/// # Possible errors
	/// * `secret::error::error_kind::ErrorKind::IncorrectKey`
	pub fn from_bytes(key: &[u8]) -> Result<Self, Error> {
		let size = match Self::define_size_as_enum(key.len()) {
			Some(key_size) => key_size,
			// Covered with `aes_from_bytes_incorrect_key` test
			None => return Err(error::new(ErrorKind::IncorrectKey)),
		};
		// Covered with `aes_from_bytes` test
		return Ok(Self { size, key: key.to_vec() })
	}

	// Covered with `aes_get_size()` test
	/// Returns a&nbsp;stored key size.
	pub fn get_size(&self) -> KeySize { self.size }

	/// Determines bytes quantity a&nbsp;given key should consist of based on
	/// a&nbsp;given `key_size` enumeration constant.
	/// # Parameters
	/// `key_size` &#x2013; Predefined key size.
	pub fn define_size_in_bytes(key_size: &KeySize) -> u32 {
		let bits_in_byte = 8;
		return match key_size {
			// Covered with `aes_define_size_in_bytes` test
			&KeySize::KeySize128 => 128 / bits_in_byte,
			// Covered with `aes_define_size_in_bytes` test
			&KeySize::KeySize192 => 192 / bits_in_byte,
			// Covered with `aes_define_size_in_bytes` test
			&KeySize::KeySize256 => 256 / bits_in_byte,
		}
	}

	/// Determines key size based on a&nbsp;given `bytes` quantity.
	///
	/// # Parameters
	/// `bytes` &#x2013; Bytes quantity an&nbsp;AES key consists of.
	fn define_size_as_enum(bytes: usize) -> Option<KeySize> {
		return match bytes {
			// Covered with `aes_define_size_as_enum()` test
			16 => Some(KeySize::KeySize128),
			// Covered with `aes_define_size_as_enum()` test
			24 => Some(KeySize::KeySize192),
			// Covered with `aes_define_size_as_enum()` test
			32 => Some(KeySize::KeySize256),
			// Covered with `aes_define_size_as_enum_inappropriate_size` test
			_ => None,
		}
	}
}

impl CommunicationKey for Aes {
	fn name(&self) -> String {
		let bits_in_key = match self.size {
			KeySize::KeySize128 => 128,
			KeySize::KeySize192 => 192,
			KeySize::KeySize256 => 256,
		};
		let mut to_return = String::from(Aes::key_type());
		to_return.push_str("-");
		to_return.push_str(&bits_in_key.to_string());
		// Covered with `communication_key_for_aes_name` test
		return to_return
	}

	fn encrypt(&self, to_encrypt: &[u8]) -> Result<Vec<u8>, Error> {
		let mut initialization_vector: Vec<u8> = vec![0; IV_SIZE];

		match OsRng::new() {
			Ok(mut random_generator) => random_generator.fill_bytes(&mut initialization_vector),
			Err(_) => return Err(error::new(ErrorKind::GenerationBlocked)),
		};

		let mut encryptor: Box<dyn Encryptor> = aes::cbc_encryptor(
			self.size, &self.key, &initialization_vector, PkcsPadding);
		let mut encrypted_data: Vec<u8> = Vec::with_capacity(
			initialization_vector.len() + to_encrypt.len());
		encrypted_data.extend(initialization_vector);
		let mut read_buffer: RefReadBuffer = RefReadBuffer::new(to_encrypt);
		let mut write_buffer_array: Vec<u8> = vec![0; BUFFER_SIZE];
		let mut write_buffer: RefWriteBuffer = RefWriteBuffer::new(
			write_buffer_array.as_mut_slice(),
		);

		loop {
			match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
				Ok(encryption_result) => {
					encrypted_data.extend(
						write_buffer.take_read_buffer().take_remaining().iter().collect::<Vec<_>>(),
					);
					if let BufferResult::BufferUnderflow = encryption_result { break; }
				},
				Err(err) => {
					error!("Fail while data encrypting with `{:?}` error", err);
					panic!("Unexpected internal error while encrypting data: `{:?}`", err);
				},
			}
		}

		// Covered with `communication_key_for_aes_encrypt` test
		return Ok(encrypted_data)
	}

	/// See related trait documentation for convention description.
	///
	/// **Security notice**. Caller has to understand that passing large
	/// `encrypted_data` will result in almost same size memory allocation in
	/// order to provide decrypted data.
	/// # Possible errors
	/// * `secret::error::error_kind::ErrorKind::IncorrectData`
	fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
		if encrypted_data.len() < IV_SIZE {
			// Covered with `communication_key_for_aes_decrypt_error_cases` test
			return Err(error::new(ErrorKind::IncorrectData))
		}

		let initialization_vector = &encrypted_data[..IV_SIZE];
		let mut decryptor = aes::cbc_decryptor(
			self.size, self.key.as_slice(), initialization_vector, PkcsPadding);

		let mut decrypted_data = Vec::with_capacity(encrypted_data.len() - IV_SIZE);
		let mut read_buffer = RefReadBuffer::new(&encrypted_data[IV_SIZE..]);
		let mut write_buffer_array = vec![0; BUFFER_SIZE];
		let mut write_buffer = RefWriteBuffer::new(write_buffer_array.as_mut_slice());

		loop {
			match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
				Ok(decryption_result) => {
					decrypted_data.extend(
						write_buffer.take_read_buffer().take_remaining().iter().collect::<Vec<_>>(),
					);
					if let BufferResult::BufferUnderflow = decryption_result {
						break;
					}
				},
				Err(err) => {
					match err {
						SymmetricCipherError::InvalidLength => {
							// Covered with
							// `communication_key_for_aes_decrypt_error_cases`
							// test
							return Err(error::new(ErrorKind::IncorrectData))
						},
						SymmetricCipherError::InvalidPadding => {
							panic!(
								"Unexpected error while decrypting data. PKCS padding is expected \
									to be appropriate for CBC encryption type"
							);
						},
					}
				},
			}
		}

		// Covered with `communication_key_for_aes_decrypt` test
		return Ok(decrypted_data)
	}

	// Covered with `communication_key_for_aes_bytes()` test
	fn bytes(&self) -> Vec<u8> { self.key.clone() }
}

impl PartialEq for Aes {
	fn eq(&self, other: &Self) -> bool {
		let self_size = Aes::define_size_in_bytes(&self.get_size());
		let other_size = Aes::define_size_in_bytes(&other.get_size());
		return self_size == other_size && self.key.as_slice() == other.key.as_slice()
	}
}

impl Debug for Aes {
	/// See trait&#x2011;related documentation.
	///
	/// _Implementation note._ Is aimed not&nbsp;to&nbsp;reveal stored key.
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		// Covered with `debug_fmt_for_aes` test
		return write!(
			f, "Aes {{ size: {}, key: [hidden] }}", Self::define_size_in_bytes(&self.size))
	}
}

#[cfg(test)]
mod tests {
	use crypto::aes::KeySize;
	use crate::secret::{Aes, CommunicationKey, Error};
	use crate::secret::error::ErrorKind;
	use crate::secret::aes::IV_SIZE;
	use rand::{OsRng, Rng};

	/// Tests `Aes::key_type()` function's happy path.
	#[test]
	fn aes_key_type() { assert_eq!("AES".to_string(), Aes::key_type()); }

	/// Tests `Aes::new_random()` function's happy path.
	#[test]
	fn aes_new_random() {
		Aes::new_random().expect("Failed to generate random 256-bit AES key");
	}

	/// Tests `Aes::from_bytes()` function's happy path.
	#[test]
	fn aes_from_bytes() {
		let encryption_key_original: Aes = Aes::new_random()
			.expect("Should have generated random 256-bit AES key");
		let encryption_key_as_bytes: Vec<u8> = encryption_key_original.bytes();
		let encryption_key_actual: Aes = Aes::from_bytes(&encryption_key_as_bytes)
			.expect("Should have generated AES encryption key from raw bytes");
		assert_eq!(
			encryption_key_original,
			encryption_key_actual,
			"Original AES key and the one, generated from raw bytes, should be equal",
		);
	}

	/// Tests `Aes::from_bytes()` function. Checks behavior while passing
	/// incorrect `key` argument.
	#[test]
	fn aes_from_bytes_incorrect_key() {
		let failed_generate_custom: Error = Aes::from_bytes(&vec![10, 20, 30])
			.expect_err(
				"Should have returned error while generating custom key due to incorrect data");
		assert_eq!(
			ErrorKind::IncorrectKey,
			failed_generate_custom.kind(),
			"Returned error kind, while generating custom key, should be different",
		);
	}

	/// Tests `CommunicationKey::name()` implementation for `Aes`. Checks all
	/// the&nbsp;possible outputs.
	#[test]
	fn communication_key_for_aes_name() {
		let mut random_generator = OsRng::new()
			.expect("Failed to instantiate random number generator");
		let key_size_with_name = [(KeySize::KeySize128, String::from("AES-128")),
			(KeySize::KeySize192, String::from("AES-192")),
			(KeySize::KeySize256, String::from("AES-256"))];
		for (key_size, expected_name) in key_size_with_name.iter() {
			let mut random_bytes = vec![0; Aes::define_size_in_bytes(&key_size) as usize];
			random_generator.fill_bytes(&mut random_bytes);
			println!("Bytes sequence to generate {} key from: {:?}", expected_name, random_bytes);
			let key = Aes::from_bytes(&random_bytes)
				.expect("Failed to instantiate AES key from bytes sequence logged above");
			assert_eq!(expected_name.to_owned(), key.name(), "AES key has incorrect name");
		}
	}

	/// Tests `Aes::encrypt()` function's happy path. Ensures that encrypting
	/// the&nbsp;same data with the&nbsp;same key each time will produce
	/// different encrypted data. Successful result of such non&#x2011;equality
	/// check means that different initialization vector is taken on each
	/// `encrypt()` function invocation.
	#[test]
	fn communication_key_for_aes_encrypt() {
		let encryption_key: Aes = Aes::new_random()
			.expect("Should have generated random 256-bit AES key");
		let data_to_encrypt: &[u8] = "Data to encrypt".as_bytes();
		let encrypted_data_1: Vec<u8> = encryption_key.encrypt(data_to_encrypt)
			.expect("Should have successfully encrypt data");
		let encrypted_data_2: Vec<u8> = encryption_key.encrypt(data_to_encrypt)
			.expect("Should have successfully encrypt data ");
		assert_ne!(
			encrypted_data_1,
			encrypted_data_2,
			"Same data, encrypted twice with the same key, should not be equal",
		);
	}

	/// Tests `Aes::encrypt()` function's happy path. Checks that passed
	/// empty&#x2011;array data causes no&nbsp;errors and produces normal output.
	#[test]
	fn communication_key_for_aes_encrypt_empty_data_to_encrypt() {
		let encryption_key: Aes = Aes::new_random()
			.expect("Should have generated random 256-bit AES key");
		encryption_key.encrypt(&[]).expect("Should have successfully encrypt empty data");
	}

	/// Tests `CommunicationKey::decrypt()` implementation for `Aes`. Tests
	/// happy path. Ensures that decrypted data is equal to the&nbsp;originally
	/// encrypted one.
	#[test]
	fn communication_key_for_aes_decrypt() {
		let encryption_key: Aes = Aes::new_random().expect("Should have generated random AES key");
		let data_to_decrypt: &[u8] = "Data to decrypt".as_bytes();
		let encrypted_data: Vec<u8> = encryption_key.encrypt(&data_to_decrypt)
			.expect("Should have successfully encrypt data");
		let decrypted_data: Vec<u8> = encryption_key.decrypt(encrypted_data.as_slice())
			.expect("Should have successfully decrypt data");
		assert_eq!(
			data_to_decrypt,
			decrypted_data.as_slice(),
			"Original data to decrypt should be equal to decrypted one",
		);
	}

	/// Tests `CommunicationKey::decrypt()` implementation for `Aes`. Tests
	/// error cases:
	/// * Passes empty array to decrypt.
	/// * Passes data to decrypt with invalid length, which
	/// does not&nbsp;fit padding.
	#[test]
	fn communication_key_for_aes_decrypt_error_cases() {
		// Pass empty array to decrypt
		let encryption_key: Aes = Aes::new_random().expect("Should have generated random AES key");
		let decryption_error: Error = encryption_key.decrypt(&[])
			.expect_err("Should have generated error while decrypting data");
		match decryption_error.kind() {
			ErrorKind::IncorrectData => (),
			err => {
				panic!(
					"Should have generated `{:?}` error. Found `{:?}`",
					ErrorKind::IncorrectData,
					err,
				)
			},
		}

		// Pass data to decrypt with invalid length
		let mut data_to_decrypt: Vec<u8> = vec![0; IV_SIZE];
		let mut random_generator: OsRng = OsRng::new()
			.expect("Should have created random number generator");
		random_generator.fill_bytes(&mut data_to_decrypt);
		data_to_decrypt.extend(vec![10, 20, 30]);
		let decryption_error: Error = encryption_key.decrypt(data_to_decrypt.as_slice())
			.expect_err(
				"Should have returned error while decrypting data with invalid length",
			);
		assert_eq!(
			ErrorKind::IncorrectData,
			decryption_error.kind(),
			"Returned data decrypting error should be different",
		);
	}

	/// Tests `CommunicationKey::bytes()` implementation for `Aes`. Tests happy
	/// path.
	#[test]
	fn communication_key_for_aes_bytes() {
		let encryption_key = Aes::new_random().expect("Should have generated random AES key");
		assert_eq!(
			encryption_key.key,
			encryption_key.bytes(),
			"Returned bytes representation of encryption key is incorrect",
		);
	}

	/// Tests `Aes::get_size()` function's happy path.
	#[test]
	fn aes_get_size() {
		let encryption_key: Aes = Aes::new_random().expect("Should have generated random AES key");
		match encryption_key.get_size() {
			KeySize::KeySize256 => (),
			_ => panic!("Returned encryption key size is incorrect"),
		}
	}

	/// Tests `Aes::define_size_in_bytes()` function's happy path.
	#[test]
	fn aes_define_size_in_bytes() {
		assert_eq!(
			16,
			Aes::define_size_in_bytes(&KeySize::KeySize128),
			"Have calculated incorrect size for 128-bits enum constant",
		);
		assert_eq!(
			24,
			Aes::define_size_in_bytes(&KeySize::KeySize192),
			"Have calculated incorrect size for 192-bits enum constant",
		);
		assert_eq!(
			32,
			Aes::define_size_in_bytes(&KeySize::KeySize256),
			"Have calculated incorrect size for 256-bits enum constant",
		);
	}

	/// Tests `Aes::define_size_as_enum()` function. Passes bytes' sizes which
	/// represent existing key sizes.
	#[test]
	fn aes_define_size_as_enum() {
		let bytes_to_define_key_size_from: usize = 16;
		let defined_key_size: KeySize =
			Aes::define_size_as_enum(bytes_to_define_key_size_from)
				.expect("Should have returned a key size");
		match defined_key_size {
			KeySize::KeySize128 => (),
			_ => {
				panic!(
					"Incorrect key size has been defined from {} bytes",
					bytes_to_define_key_size_from,
				)
			},
		}

		let bytes_to_define_key_size_from: usize = 24;
		let defined_key_size: KeySize =
			Aes::define_size_as_enum(bytes_to_define_key_size_from)
				.expect("Should have returned a key size");
		match defined_key_size {
			KeySize::KeySize192 => (),
			_ => {
				panic!(
					"Incorrect key size has been defined from {} bytes",
					bytes_to_define_key_size_from,
				)
			},
		}

		let bytes_to_define_key_size_from: usize = 32;
		let defined_key_size: KeySize =
			Aes::define_size_as_enum(bytes_to_define_key_size_from)
				.expect("Should have returned a key size");
		match defined_key_size {
			KeySize::KeySize256 => (),
			_ => {
				panic!(
					"Incorrect key size has been defined from {} bytes",
					bytes_to_define_key_size_from,
				)
			},
		}
	}

	/// Tests `Aes::define_size_as_enum()` function. Passes inappropriate bytes
	/// length.
	#[test]
	fn aes_define_size_as_enum_inappropriate_size() {
		let bytes_to_define_key_size_from: usize = 1;
		let defined_key_size: Option<KeySize> =
			Aes::define_size_as_enum(bytes_to_define_key_size_from);
		match defined_key_size {
			None => (),
			Some(_) => {
				panic!(
					"Should not have returned a `KeySize` for incorrect key \
						size in bytes",
				)
			},
		}
	}

	/// Tests `PartialEq::eq()` function's implementation for `Aes` struct.
	#[test]
	fn partial_eq_eq_for_aes() {
		let encryption_key_1: Aes = Aes::new_random()
			.expect("Should have successfully generated random AES key");
		let encryption_key_2: Aes = Aes::from_bytes(encryption_key_1.bytes().as_slice())
			.expect("Should have successfully generated custom AES key");
		assert_eq!(
			encryption_key_1,
			encryption_key_2,
			"AES encryption keys should be equal",
		);
		let encryption_key_2: Aes = Aes::new_random()
			.expect("Should have successfully generated random AES key");
		assert_ne!(
			encryption_key_1,
			encryption_key_2,
			"AES encryption keys should not be equal",
		);
	}

	/// Tests `Debug::fmt()` implementation for `Aes`. Happy path is checked.
	/// This test ensures that `Aes.key` field is not&nbsp;revealed.
	#[test]
	fn debug_fmt_for_aes() {
		let key = Aes::new_random().expect("Failed to instantiate random AES key");
		let expected_size = Aes::define_size_in_bytes(&KeySize::KeySize256);
		assert_eq!(
			format!("Aes {{ size: {}, key: [hidden] }}", expected_size),
			format!("{:?}", key),
			"`Aes` struct's debug representation is incorrect",
		)
	}
}
