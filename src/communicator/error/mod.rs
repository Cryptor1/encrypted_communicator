mod kind;

pub use self::kind::Kind;

/// Represents error occurred while operating with `Communicator`.
#[derive(Debug)]
pub struct Error {
	/// Kind of communication error.
	kind: Kind,
}

impl Error {
	// Covered with `error_kind()` test
	/// Returns error kind represented by an&nbsp;instance.
	pub fn kind(&self) -> &Kind { &self.kind }
}

// Covered with `error_mod_new()` test
/// Creates `Error` with specified `kind`.
pub fn new(kind: Kind) -> Error { Error { kind } }

#[cfg(test)]
mod tests {
	use crate::communicator::error;
	use crate::communicator::{Error, Kind};

	/// Tests `Error::kind()` function's happy path.
	#[test]
	fn error_kind() {
		let error: Error = Error { kind: Kind::InappropriateData };
		match error.kind() {
			Kind::InappropriateData => (),
			incorrect_kind => {
				panic!("Error struct contains incorrect, `{:?}`, kind of error", incorrect_kind)
			},
		}
	}

	/// Tests `new()` function's happy path.
	#[test]
	fn error_mod_new() { error::new(Kind::DataDecryption); }
}
