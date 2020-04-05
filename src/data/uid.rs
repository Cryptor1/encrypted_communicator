//! Represents unique identifier of a&nbsp;given communicator instance.

use crate::data::error;
use crate::data::error::Error;
use crate::data::error::Kind;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use pnet::datalink;
use pnet_datalink::NetworkInterface;
use regex::Regex;
use thread_id;

use std::ffi::OsString;
use std::fmt::Display;
use std::fmt;
use std::fmt::Formatter;
use std::fs;
use std::fs::DirEntry;
use std::fs::File;
use std::io;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time;
use std::time::SystemTime;

lazy_static! {
	// A regular expression pattern used to determine whether a given
	// SHA-256 sum is valid
	static ref UID_REGEX: Regex = Regex::new(r"^[0-9a-f]{64}$").unwrap();
}

/// Unique identifier of a&nbsp;given communicator.
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Uid {
	/// Unique identifier in the&nbsp;form of SHA&#x2011;256 hash.
	value: String,
}

impl Uid {
	/// Creates unique identifier based on `sha256`.
	///
	/// _Implementation note._ `sha256` gets lowercased before further
	/// processing.
	/// # Parameters
	/// * `sha256` &ndash; String in the&nbsp;form of <u>valid</u>
	/// SHA&#x2011;256 hash sum.
	/// # Possible errors
	/// * `Kind::InvalidUid`
	pub fn from_string(sha256: &str) -> Result<Self, Error> {
		let sha256 = sha256.to_ascii_lowercase();
		return if UID_REGEX.is_match(&sha256) {
			// Covered with `uid_from_string()` test
			Ok(Self { value: String::from(sha256) })
		// Covered with `uid_from_string_incorrect_identifier()` test
		} else { Err(error::new(Kind::InvalidUid)) }
	}

	/// Generates unique identifier. Returned UID is the&nbsp;best effort to
	/// make identifier as unique as possible.
	/// # Possible errors
	/// * `Kind::UidGeneration` &#x2013; Cannot gather enough system data to
	/// generate entirely unique identifier.
	pub fn generate_totally_unique() -> Result<Self, Error> {
		let data_chunks_to_collect: usize = 3;
		// Important. Fill the vector with exactly `data_chunks_to_collect`
		// elements
		let mut data_gathered: Vec<bool> = Vec::with_capacity(data_chunks_to_collect);

		let mut mac_addresses: Vec<String> = vec![];
		if cfg!(unix) {
			let path: &Path = Path::new("/sys/class/net");
			match fs::read_dir(path) {
				Ok(subfolders) => {
					mac_addresses = subfolders.filter_map(
						|subfolder: io::Result<DirEntry>| -> Option<DirEntry> {
							return subfolder.ok()
						}
					)
						.map(
							|subfolder: DirEntry| -> OsString {
								return subfolder.path()
									.file_name()
									.expect(
										"`..` subfolder is not expected to be \
											returned by iterator",
									)
									.to_os_string()
							}
						)
						.filter_map(
							|subfolder_name: OsString| -> Option<String> {
								return subfolder_name.into_string().ok()
							}
						)
						.filter_map(
							|subfolder_name: String| -> Option<String> {
								let path_to_file: PathBuf = path.join(
									subfolder_name.as_str(),
								)
									.join("address");
								let mut file: File = match File::open(path_to_file) {
									Ok(file) => file,
									Err(_) => return None,
								};
								let mut mac_address: String = String::new();
								if let Err(_) = file.read_to_string(&mut mac_address) {
									return None
								}
								return Some(mac_address)
							}
						)
						.collect();

					if mac_addresses.is_empty() { data_gathered.push(false); }
					else { data_gathered.push(true); }
				},

				Err(err) => {
					warn!(
						"Failed to obtain MAC addresses due to following IO \
							error: `{:?}`",
						err.kind(),
					);
					data_gathered.push(false);
				},
			}
		}

		let mut hash_feed: String = String::new();
		for mac_address in mac_addresses { hash_feed += &mac_address; }
		hash_feed += &thread_id::get().to_string();

		let ip_addresses: Vec<String> = datalink::interfaces().iter()
			.map(
				|network_interface: &NetworkInterface| -> String {
					return network_interface.ips.iter().map(
						|ip_network| -> IpAddr { ip_network.ip() }
					)
						.map(
							|ip_address: IpAddr| -> String {
								match ip_address {
									IpAddr::V4(ip_address) => {
										let octets: Vec<String> = ip_address.octets().iter()
											.map( |octet: &u8| -> String { octet.to_string() })
											.collect();
										let mut to_return: String = String::new();
										for octet in octets { to_return += &octet; }
										return to_return
									},
									IpAddr::V6(ip_address) => {
										let segments: Vec<String> = ip_address.segments().iter()
											.map( |segment: &u16| -> String { segment.to_string() })
											.collect();
										let mut to_return: String = String::new();
										for segment in segments { to_return += &segment; }
										return to_return
									},
								}
							}
						)
						.collect()
				}
			)
			.collect();

		if ip_addresses.is_empty() { data_gathered.push(false); }
		else { data_gathered.push(true); }
		for ip_address in ip_addresses { hash_feed += &ip_address; }

		match SystemTime::now().duration_since(time::UNIX_EPOCH) {
			Ok(timestamp) => {
				hash_feed += &(timestamp.as_secs() * 1e+9 as u64
					+ timestamp.subsec_nanos() as u64).to_string();
				data_gathered.push(true);
			},
			Err(_) => {
				warn!(
					"Failed to obtain a time duration from POSIX time. \
						Possible reason is that system time is incorrect and \
						has value before Unix epoch",
				);
				data_gathered.push(false);
			},
		}

		if data_gathered.len() != data_chunks_to_collect {
			panic!(
				"Internal error: Gathered for unique identifier generation data \
					counting is incorrect",
			)
		}

		let successfully_gathered_data_quantity: usize = data_gathered.iter()
			.filter( |data_chunk_obtained: &&bool| -> bool { **data_chunk_obtained })
			.count();

		// Perceive collected data as insufficient for generating an entirely
		// unique identifier
		if successfully_gathered_data_quantity < data_chunks_to_collect - 1 {
			return Err(error::new(Kind::UidGeneration))
		} else {
			let mut digest: Sha256 = Sha256::new();
			digest.input_str(&hash_feed);
			return Ok(Self { value: digest.result_str() })
		}
	}

	/// Returns SHA sum stored in this `Uid`.
	pub fn plain_value(&self) -> String { self.value.clone() }
}

impl Display for Uid {
	fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
		// Covered with `display_fmt_for_uid` test
		return write!(formatter, "{}", self.value)
	}
}

#[cfg(test)]
mod tests {
	use rand::{OsRng, Rng};
	use crate::data::error::Error;
	use crate::data::error::Kind;
	use crate::data::Uid;

	/// Tests `Uid::from_string()` function's happy path.
	#[test]
	fn uid_from_string() {
		let mut generator: OsRng = OsRng::new()
			.expect(
				"Failed to initialize random number generator. Note: The issue \
					might not related to the crate implementation"
			);
		let valid_sha256_characters: [char; 22] = ['0', '1', '2', '3', '4', '5', '6',
			'7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F'];
		let string_identifier_length: usize = 64;

		let mut attempt: usize = 0;
		loop {
			attempt += 1;
			let mut string_identifier: String = String::with_capacity(
				string_identifier_length,
			);
			let mut random_generator_counter: usize = 0;
			loop {
				let random_value: &char = generator.choose(&valid_sha256_characters)
					.expect(
						"Internal error: Test implementation contains logic bug. \
						No allowed values are provided for random generator to \
						be sampled"
					);
				string_identifier.push(*random_value);
				random_generator_counter += 1;
				if random_generator_counter == string_identifier_length { break }
			}
			println!(
				"String identifier to convert to `Uid` object: `{}`",
				string_identifier,
			);
			Uid::from_string(&string_identifier)
				.expect("Failed to convert string identifier to `Uid` object");
			if attempt == 100 { break }
		}
	}

	/// Tests `Uid::from_string()` function's error case. The&nbsp;case when
	/// the&nbsp;mentioned function receives incorrect `sha256` argument is
	/// checked.
	#[test]
	fn uid_from_string_incorrect_identifier() {
		let error: Error = Uid::from_string("Broken identifier")
			.expect_err("Should return error while parsing");
		match error.kind() {
			Kind::InvalidUid => (),
			_ => panic!("Should return `{:?}` error kind", Kind::InvalidUid),
		}
	}

	/// Tests `Uid::generate_totally_unique()` function's happy path. Ensures
	/// each function call produces different unique identifiers.
	#[test]
	fn uid_generate_totally_unique() {
		let error_message: &str = "Should have generated unique identifier";
		let unique_identifier1: Uid = Uid::generate_totally_unique()
			.expect(error_message);
		let unique_identifier2: Uid = Uid::generate_totally_unique()
			.expect(error_message);
		assert_ne!(
			unique_identifier1,
			unique_identifier2,
			"Generated unique identifiers should be different",
		);
	}

	/// Tests `Display::fmt()` implementation for `Uid`.
	#[test]
	fn display_fmt_for_uid() {
		let unique_identifier = Uid::generate_totally_unique()
			.expect("Should have generated unique identifier");
		assert_eq!(
			format!("{}", unique_identifier.value),
			format!("{}", unique_identifier),
			"`Uid` is not correctly printed in user-facing format",
		);
	}

	/// Tests `Uid::plain_value()` function's happy path.
	#[test]
	fn uid_plain_value() {
		let unique_identifier: Uid = Uid::generate_totally_unique()
			.expect("Should have generated unique identifier");
		let actual_value: String = unique_identifier.plain_value();
		assert_eq!(
			unique_identifier.value,
			actual_value,
			"Obtained plain value of unique identifier differs from the actually stored",
		)
	}
}
