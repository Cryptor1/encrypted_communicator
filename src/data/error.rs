mod kind;

pub use self::kind::Kind;

/// Error which occurred while operating with `data` module.
#[derive(Debug, PartialEq)]
pub struct Error {
	/// Error kind.
	kind: Kind,
}

impl Error {
	/// Returns the&nbsp;error kind.
	pub fn kind(&self) -> &Kind { &self.kind }
}

/// Sole constructor.
pub fn new(kind: Kind) -> Error { Error { kind } }

#[cfg(test)]
mod tests {
	use crate::data::Error;
	use crate::data::error;
	use crate::data::error::Kind;

	/// Tests `Error::kind()` function's happy path. Ensures that returned error
	/// kind is the&nbsp;same as used at initialization time.
	#[test]
	fn error_kind() {
		let error: Error = error::new(Kind::NoSize);
		assert_eq!(
			&Kind::NoSize,
			error.kind(),
			"`Error` struct has been initialized with another than returned kind",
		);
	}

	/// Tests `error::new()` function's happy path.
	#[test]
	fn error_mod_new() { error::new(Kind::NoSize); }
}
