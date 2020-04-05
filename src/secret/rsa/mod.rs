mod key_size;

pub use self::key_size::RsaKeySize;

use openssl::error::ErrorStack;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rsa::{Rsa as OpenSslRsa, Padding};
use crate::secret::{error, Error, ErrorKind};
use crate::secret::negotiation_key::NegotiationKey;

pub struct Rsa {
	key: Type,
}

impl Rsa {
	pub fn new(size: RsaKeySize) -> Result<Self, Error> {
		let result = OpenSslRsa::generate(key_size::in_bits(size));
		match result {
			// Covered with `rsa_new` test
			Ok(key) => return Ok(Rsa { key: Type::Whole(key) }),
			Err(error_stack) => {
				let error_message = format!(
					"Private RSA key generation error: `{}`", error_stack.to_string());
				return Err(error::new(ErrorKind::GenerationFailed(Some(error_message))))
			},
		};
	}

	pub fn new_public_from_pem(bytes: &[u8]) -> Result<Self, Error> {
		let result = OpenSslRsa::public_key_from_pem(bytes);
		match result {
			// Covered with `rsa_new_public_from_pem` test
			Ok(key) => return Ok(Rsa { key: Type::Public(key) }),
			Err(error_stack) => {
				let error_message = format!(
					"Public RSA key generation error: `{}`", error_stack.to_string());
				// Covered with `rsa_new_public_from_pem_inappropriate_bytes`
				// test
				return Err(error::new(ErrorKind::GenerationFailed(Some(error_message))))
			},
		}
	}

	pub fn public_part(&self) -> Self {
		// Covered with `rsa_public_part` test
		return Self::new_public_from_pem(NegotiationKey::public_part(self).as_slice())
			.expect("Internal error: Failed to obtain public key")
	}
}

impl NegotiationKey for Rsa {
	fn name(&self) -> String {
		let mut name: String = "RSA-".to_owned();
		let size: u32 = match &self.key {
			Type::Whole(key) => key.size(),
			Type::Public(key) => key.size(),
		};
		name.push_str((size * 8).to_string().as_str());
		// Covered with `negotiation_key_name_for_rsa` test
		return name;
	}

	fn has_private(&self) -> bool {
		// Covered with `negotiation_key_has_private_for_rsa_true_case` test
		if let Type::Whole(_) = &self.key { return true }
		// Covered with `negotiation_key_has_private_for_rsa_false_case` test
		return false
	}

	// Covered with `negotiation_key_has_public_for_rsa_whole()` and
	// `negotiation_key_has_public_for_rsa_public()` tests
	fn has_public(&self) -> bool { true }

	fn decrypt_with_private(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
		let key: &OpenSslRsa<Private> = if let Type::Whole(key) = &self.key {
			&key
		} else {
			// Covered with
			// `negotiation_key_decrypt_with_private_no_private_part` test
			panic!("This instance of RSA key does not contain private part")
		};
		let mut decrypted_data: Vec<u8> = vec![0; key.size() as usize];
		let decryption_result: Result<usize, ErrorStack> = key.private_decrypt(
			data, decrypted_data.as_mut_slice(), Padding::PKCS1_OAEP);
		let meaningful_bytes: usize = match decryption_result {
			Ok(bytes) => bytes,
			Err(error_stack) => {
				let error_message = format!(
					"Failed to decrypt data using RSA key. Reason: `{}`", error_stack);
				// Covered with
				// `negotiation_key_decrypt_with_private_for_rsa_decryption_failure`
				// test
				return Err(error::new(ErrorKind::DecryptionFailed(Some(error_message))))
			},
		};
		let mut decrypted_data_index: usize = 0;
		decrypted_data.retain(|_| {
			let result: bool = decrypted_data_index < meaningful_bytes;
			decrypted_data_index += 1;
			return result;
		});
		// Covered with `negotiation_key_decrypt_with_private_for_rsa` test
		return Ok(decrypted_data)
	}

	fn encrypt_with_public(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
		match &self.key {
			Type::Whole(key) => {
				let mut encrypted_data: Vec<u8> = vec![0; key.size() as usize];
				let encryption_result: Result<usize, ErrorStack> = key.public_encrypt(
					data, encrypted_data.as_mut_slice(), Padding::PKCS1_OAEP);
				if let Err(error_stack) = encryption_result {
					let error_message = format!(
						"Failed to encrypt data using RSA key. Reason: `{}`", error_stack);
					return Err(error::new(ErrorKind::EncryptionFailed(Some(error_message))))
				}
				// Covered with
				// `negotiation_key_encrypt_with_public_for_rsa_whole` test
				return Ok(encrypted_data)
			},
			Type::Public(key) => {
				let mut encrypted_data: Vec<u8> = vec![0; key.size() as usize];
				let encryption_result: Result<usize, ErrorStack> = key.public_encrypt(
					data, encrypted_data.as_mut_slice(), Padding::PKCS1_OAEP);
				if let Err(error_stack) = encryption_result {
					let error_message = format!(
						"Failed to encrypt data using RSA key. Reason: `{}`", error_stack);
					return Err(error::new(ErrorKind::EncryptionFailed(Some(error_message))))
				}
				// Covered with
				// `negotiation_key_encrypt_with_public_for_rsa_public` test
				return Ok(encrypted_data)
			}
		}
	}

	fn private_part(&self) -> Vec<u8> {
		if let Type::Whole(key) = &self.key {
			// Covered with `negotiation_key_private_part_for_rsa` test
			return key.private_key_to_pem()
				.expect(
					"Internal error: Failed to serialize private asymmetric key part into \
						a PEM-encoded PKCS#1 RSAPrivateKey structure",
				)
		}
		// Covered with `negotiation_key_private_part_for_rsa_no_private_part`
		// test
		panic!("An instance of this asymmetric key does not contain private part")
	}

	fn public_part(&self) -> Vec<u8> {
		match &self.key {
			Type::Whole(key) => {
				// Covered with `rsa_public_part` test
				return key.public_key_to_pem()
					.expect(
						"Internal error: Failed to serialize public asymmetric key part into \
							a PEM-encoded SubjectPublicKeyInfo structure",
					)
			},
			Type::Public(key) => {
				// Covered with `rsa_public_part` test
				return key.public_key_to_pem().expect(
					"Internal error: Failed to serialize public asymmetric key part into \
						a PEM-encoded SubjectPublicKeyInfo structure",
				)
			},
		}
	}
}

enum Type {
	Whole(OpenSslRsa<Private>),
	Public(OpenSslRsa<Public>),
}

#[cfg(test)]
mod tests {
	use openssl::pkey::Public;
	use openssl::rsa::Rsa as OpenSslRsa;
	use crate::secret::rsa::{key_size, Rsa, RsaKeySize, Type};
	use crate::secret::negotiation_key::NegotiationKey;
	use crate::secret::ErrorKind;

	const ALL_RSA_SIZES: [RsaKeySize; 3] = [RsaKeySize::Rsa1024,
		RsaKeySize::Rsa2048, RsaKeySize::Rsa4096];

	/// Tests `Rsa::new()` function's happy path.
	#[test]
	fn rsa_new() {
		for &size in ALL_RSA_SIZES.iter() {
			Rsa::new(size).expect(&format!("Failed to instantiate RSA key with `{:?}` size", size));
		}
	}

	/// Tests `Rsa::new_public_from_pem()` function's happy path. Checks key
	/// instantiation with all supported sizes.
	#[test]
	fn rsa_new_public_from_pem() {
		for &size in ALL_RSA_SIZES.iter() {
			let rsa_key_whole = Rsa::new(size)
				.expect(&format!("Failed to instantiate RSA key with `{:?}` size", size));
			let public_part_raw_bytes = NegotiationKey::public_part(&rsa_key_whole);
			println!(
				"Bytes which are going to be used to instantiate public RSA key: {:?}",
				public_part_raw_bytes,
			);
			Rsa::new_public_from_pem(&public_part_raw_bytes)
				.expect("Failed to instantiate public RSA key with `{:?}` size from raw bytes");
		}
	}

	/// Tests `Rsa::new_public_from_pem()` function's error path. Ensures RSA
	/// key is not&nbsp;created with inappropriate bytes sequence.
	#[test]
	fn rsa_new_public_from_pem_inappropriate_bytes() {
		match Rsa::new_public_from_pem(&[10, 20, 30]) {
			Err(_) => (),
			Ok(_) => panic!("Public RSA key has been created with inappropriate bytes sequence"),
		}
	}

	/// Tests `Rsa::public_part()` function.
	#[test]
	fn rsa_public_part() {
		// Test with `Type::Whole` key type
		let rsa_key: Rsa = new_rsa_whole(RsaKeySize::Rsa4096);
		if let Type::Whole(key) = &rsa_key.key {
			let expected_structure = key.public_key_to_pem()
				.expect(
					"Failed to serialize public RSA key into a PEM-encoded SubjectPublicKeyInfo \
					structure"
				);
			assert_eq!(
				NegotiationKey::public_part(&rsa_key),
				expected_structure,
				"Obtained RSA key public part is not correct",
			);
		}
		else { panic!("Unexpected `secret::rsa::Type`. Is expected to be `Type::Whole`") }

		// Test with `Type::Public` key type
		let rsa_key: Rsa = new_rsa_public(RsaKeySize::Rsa4096);
		if let Type::Public(key) = &rsa_key.key {
			assert_eq!(
				NegotiationKey::public_part(&rsa_key),
				key.public_key_to_pem().expect("Failed to retrieve public part from RSA key"),
				"Retrieved public RSA key part is incorrect",
			);
		}
		else { panic!("Unexpected `secret::rsa::Type`. Is expected to be `Type::Public`") }
	}

	/// Tests `NegotiationKey::name()` implementation for `Rsa`. Tests happy
	/// path for all possible `RsaKeySize`s.
	#[test]
	fn negotiation_key_name_for_rsa() {
		let key_size = RsaKeySize::Rsa1024;
		let rsa_key = Rsa::new(key_size)
			.expect(&format!("Failed to instantiate RSA key with `{:?}` size", key_size));
		assert_eq!(
			"RSA-1024", rsa_key.name(), "RSA key with `{:?}` size has incorrect name", key_size);

		let key_size = RsaKeySize::Rsa2048;
		let rsa_key = Rsa::new(key_size)
			.expect(&format!("Failed to instantiate RSA key with `{:?}` size", key_size));
		assert_eq!(
			"RSA-2048", rsa_key.name(), "RSA key with `{:?}` size has incorrect name", key_size);

		let key_size = RsaKeySize::Rsa4096;
		let rsa_key = Rsa::new(key_size)
			.expect(&format!("Failed to instantiate RSA key with `{:?}` size", key_size));
		assert_eq!(
			"RSA-4096", rsa_key.name(), "RSA key with `{:?}` size has incorrect name", key_size);
	}

	/// Tests `NegotiationKey::has_private()` implementation for `Rsa`. Tests
	/// <u>true</u> case.
	/// # See also
	/// `negotiation_key_has_private_for_rsa_false_case()`
	#[test]
	fn negotiation_key_has_private_for_rsa_true_case() {
		let rsa_key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key");
		if !rsa_key.has_private() {
			panic!("RSA key does not contain private part")
		}
	}

	/// Tests `NegotiationKey::has_private()` implementation for `Rsa`. Tests
	/// <u>false</u> case.
	/// # See also
	/// `negotiation_key_has_private_for_rsa_true_case()`
	#[test]
	fn negotiation_key_has_private_for_rsa_false_case() {
		let rsa_key = Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to instantiate RSA key with private and public parts")
			.public_part();
		if rsa_key.has_private() {
			panic!("RSA key must not contain private part")
		}
	}

	/// Tests `NegotiationKey::has_public()` implementation for `Rsa`. Tests
	/// case when `Rsa` has private and public parts.
	/// # See also
	/// `negotiation_key_has_public_for_rsa_public()`
	#[test]
	fn negotiation_key_has_public_for_rsa_whole() {
		let rsa_key = Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to instantiate RSA key with private and public parts");
		if !rsa_key.has_public() {
			panic!("RSA key does not contain public part")
		}
	}

	/// Tests `NegotiationKey::has_public()` implementation for `Rsa`. Tests
	/// case when `Rsa` has public part only.
	/// # See also
	/// `negotiation_key_has_public_for_rsa_whole()`
	#[test]
	fn negotiation_key_has_public_for_rsa_public() {
		let rsa_key = Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to instantiate RSA key with private and public parts")
			.public_part();
		if !rsa_key.has_public() {
			panic!("RSA key does not contain public part")
		}
	}

	/// Tests `NegotiationKey::decrypt_with_private()` implementation for `Rsa`.
	/// Ensures the&nbsp;mentioned function panics when an&nbsp;`Rsa` instance
	/// does not&nbsp;have private part.
	#[test]
	#[should_panic(expected = "This instance of RSA key does not contain private part")]
	fn negotiation_key_decrypt_with_private_for_rsa_no_private_part() {
		let key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key")
			.public_part();
		#[allow(unused_must_use)] {
			key.decrypt_with_private(&[10, 20, 30]);
		}
	}

	/// Tests `NegotiationKey::decrypt_with_private()` implementation for `Rsa`.
	/// Ensures the&nbsp;mentioned function returns
	/// `ErrorKind::DecryptionFailed` error when inappropriate data has been
	/// passed for decryption.
	#[test]
	fn negotiation_key_decrypt_with_private_for_rsa_decryption_failure() {
		let key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key");
		let decryption_result = key.decrypt_with_private(
			"Inappropriate data to decrypt".as_bytes());
		let error_kind = match decryption_result {
			Ok(result_data) => {
				panic!(
					"`Rsa` instance has successfully processed inappropriate data passed for \
						decryption. Following bytes have been obtained after processing: {:?}",
					result_data,
				)
			},
			Err(err) => err.kind(),
		};
		if let ErrorKind::DecryptionFailed(reason) = error_kind {
			let message = reason.expect(
				"`Rsa` instance returned expected error while processing inappropriate data for \
					decryption, but error has no reason message",
			);
			assert!(message.contains("Failed to decrypt data using RSA key. Reason: `"));
		} else {
			panic!(
				"`Rsa` instance returned incorrect, `{:?}`, error while processing inappropriate \
					data for decryption",
				error_kind,
			)
		}
	}

	/// Tests `NegotiationKey::decrypt_with_private()` implementation for `Rsa`.
	/// Tests happy path.
	#[test]
	fn negotiation_key_decrypt_with_private_for_rsa() {
		let whole_key = Rsa::new(RsaKeySize::Rsa1024)
			.expect("Failed to instantiate RSA key with private and public parts");
		let public_part = NegotiationKey::public_part(&whole_key);
		let public_part = Rsa::new_public_from_pem(&public_part)
			.expect("Failed to instantiate RSA key with public part only");
		let to_encrypt = "Data to encrypt".as_bytes();
		let encrypted_data = public_part.encrypt_with_public(to_encrypt)
			.expect("Failed to encrypt data using public RSA key");
		let decrypted_data = whole_key.decrypt_with_private(&encrypted_data)
			.expect("Failed to decrypt data using private RSA key");
		assert_eq!(
			to_encrypt,
			decrypted_data.as_slice(),
			"Data decryption with private RSA key produced incorrect result",
		);
	}

	/// Tests `NegotiationKey::encrypt_with_public()` implementation for `Rsa`.
	/// Ensures data after encryption process is not&nbsp;equal to data that was
	/// passed for encryption. The&nbsp;case when `Rsa` struct is initialized
	/// with `Type::Whole` is checked.
	#[test]
	fn negotiation_key_encrypt_with_public_for_rsa_whole() {
		let key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key");
		let to_encrypt = "Data to encrypt".as_bytes();
		let encrypted_data = key.encrypt_with_public(&to_encrypt)
			.expect("Failed to encrypt data using public RSA key part");
		assert_eq!(128, encrypted_data.len(), "Encrypted data length in bytes is incorrect");
	}

	/// Tests `NegotiationKey::encrypt_with_public()` implementation for `Rsa`.
	/// Ensures data after encryption process is not&nbsp;equal to data that was
	/// passed for encryption. The&nbsp;case when `Rsa` struct is initialized
	/// with `Type::Public` is checked.
	#[test]
	fn negotiation_key_encrypt_with_public_for_rsa_public() {
		let key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key")
			.public_part();
		let to_encrypt = "Data to encrypt".as_bytes();
		let encrypted_data = key.encrypt_with_public(&to_encrypt)
			.expect("Failed to encrypt data using public RSA key part");
		assert_eq!(128, encrypted_data.len(), "Encrypted data length in bytes is incorrect");
	}

	/// Tests `NegotiationKey::private_part()` implementation for `Rsa`. Happy
	/// path is checked.
	#[test]
	fn negotiation_key_private_part_for_rsa() {
		let key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key");
		let expected_data = if let Type::Whole(key) = &key.key {
			key.private_key_to_pem()
				.expect(
					"Failed to serialize private asymmetric key part into a PEM-encoded PKCS#1 \
						RSAPrivateKey structure",
				)
		} else {
			panic!(
				"An instance of `Rsa` struct has been incorrectly initialized: It does not contain \
					private part as expected",
			)
		};
		assert_eq!(expected_data, key.private_part(), "Obtained private RSA key part is incorrect");
	}

	/// Tests `NegotiationKey::private_part()` implementation for `Rsa`. Ensures
	/// the&nbsp;mentioned implementation panics when an&nbsp;instance of `Rsa`
	/// struct does not&nbsp;contain private key.
	#[test]
	#[should_panic(expected = "An instance of this asymmetric key does not contain private part")]
	fn negotiation_key_private_part_for_rsa_no_private_part() {
		let key = Rsa::new(RsaKeySize::Rsa1024).expect("Failed to instantiate RSA key")
			.public_part();
		key.private_part();
	}

	fn new_rsa_whole(size: RsaKeySize) -> Rsa {
		let key = OpenSslRsa::generate(key_size::in_bits(size))
			.expect("Failed to instantiate RSA key");
		return Rsa { key: Type::Whole(key) }
	}

	fn new_rsa_public(size: RsaKeySize) -> Rsa {
		let rsa_whole: Rsa = new_rsa_whole(size);
		if let Type::Whole(key) = rsa_whole.key {
			let rsa_public: OpenSslRsa<Public> = OpenSslRsa::public_key_from_pem(
				key.public_key_to_pem()
					.expect("Failed to fetch public part from RSA key")
					.as_slice(),
			)
				.expect(
					"Failed to decode PEM-encoded SubjectPublicKeyInfo structure with public RSA \
						key",
				);
			return Rsa { key: Type::Public(rsa_public) }
		}
		panic!(
			"Internal error: Failed to instantiate `secret::rsa::Rsa` structure with public key \
				only. Reason: Unexpected `secret::rsa::Type` has been prepared to retrieve public \
				key part from. Is expected to be `Type::Whole`",
		)
	}
}
