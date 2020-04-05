use regex::Regex;

use super::error;
use super::error::Error;
use super::error::Kind;

lazy_static! {
	// Used to determine whether `Version` is `Version::Ver0_1`
	static ref VER0_1_REGEX: Regex = Regex::new(r"0\.1(\.\d+)?").unwrap();
}

/// Communication version used to define the rules used to communicate between
/// instances of the Encrypted Communicator.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Version {
	/// Denotes v.0.1 communication version.
	Ver0_1,
}

/// Determines enum equivalent of a&nbsp;communication version.
/// # Parameters
/// `version` &ndash; Communication version.
/// # Possible errors
/// * `data::error::kind::Kind::HeaderData`
/// # See also
/// * `data::RoughHeader::version`
/// * `data::Data::version`
pub fn define_version(version: &str) -> Result<Version, Error> {
	if VER0_1_REGEX.is_match(version) { return Ok(Version::Ver0_1) }
	return Err(error::new(Kind::HeaderData))
}

/// Determines semver string equivalent of a&nbsp;communication version.
pub fn version_as_string(version: Version) -> String {
	return match version {
		Version::Ver0_1 => "0.1".to_owned(),
	}
}

#[cfg(test)]
mod tests {
	use crate::data::Error;
	use crate::data::error::Kind;
	use crate::data::{version, Version};

	/// Tests `version::define_version()` function's happy path.
	#[test]
	fn version_mod_define_version() {
		let derived_version: Version = version::define_version("0.1")
			.expect("Should have successfully derived version of `0.1` version literal");
		// Panic on incorrect versions
		match derived_version {
			Version::Ver0_1 => (),
		}
	}

	/// Tests `version::define_version()` function's error path. Passes
	/// incorrect value as `version` argument.
	#[test]
	fn version_mod_define_version_incorrect_version() {
		let version_error: Error = version::define_version("dummy")
			.expect_err("Should have returned error instead of derived version");
		assert_eq!(Kind::HeaderData, *version_error.kind());
	}

	/// Tests `version::version_as_string()` function's happy path.
	#[test]
	fn version_mod_define_version_as_number() {
		let version_as_string = version::version_as_string(Version::Ver0_1);
		assert_eq!("0.1", version_as_string);
	}
}
