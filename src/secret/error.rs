mod error_kind;

pub use self::error_kind::ErrorKind;

/// Error which occurred while performing actions over encryption key.
#[derive(Debug)]
pub struct Error {
	/// Type of error occurred while performing actions over encryption key.
	kind: ErrorKind,
}

impl Error {
	/// Returns the&nbsp;kind of error which occurred while performing actions
	/// over encryption key.
	pub fn kind(&self) -> ErrorKind { self.kind.clone() }
}

/// Serves as a&nbsp;sole constructor for the&nbsp;`Error` struct.
///
/// # Parameters
/// `kind` &#x2013; Type of error occurred while performing actions over
/// encryption key.
pub fn new(kind: ErrorKind) -> Error { Error { kind } }

#[cfg(test)]
mod tests {
	use crate::secret::{Error, error, ErrorKind};

	/// Tests `Error::kind()` function's happy path.
	#[test]
	fn error_kind() {
		let error: Error = error::new(ErrorKind::IncorrectData);
		assert_eq!(
			ErrorKind::IncorrectData,
			error.kind(),
			"Obtained error is not the one error struct has been initialized with",
		);
	}

	/// Tests `error::new()` function's happy path.
	#[test]
	fn error_mod_new() { error::new(ErrorKind::IncorrectData); }
}
