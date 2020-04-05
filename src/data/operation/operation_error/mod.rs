mod kind;

pub use self::kind::ErrorKind;

/// Error which occurred while working with `Operation`.
#[derive(Debug)]
pub struct OperationError {
	/// Operation error kind.
	kind: ErrorKind,
}

impl OperationError {
	/// Returns operation error kind.
	pub fn kind(&self) -> ErrorKind { self.kind }
}

/// Serves as a&nbsp;sole constructor for the&nbsp;`OperationError` struct.
///
/// # Parameters
/// `kind` &#x2013; Operation error kind.
pub fn new(kind: ErrorKind) -> OperationError { OperationError { kind } }

#[cfg(test)]
mod tests {
	use crate::data::OperationError;
	use crate::data::operation::operation_error;
	use crate::data::operation::operation_error::ErrorKind;

	/// Tests `OperationError::kind()` function's happy path.
	#[test]
	fn operation_error_kind() {
		let expected_error_kind: ErrorKind = ErrorKind::IncorrectEstablishData;
		let operation_error: OperationError = operation_error::new(expected_error_kind);
		assert_eq!(
			expected_error_kind,
			operation_error.kind(),
			"`OperationError` struct should contain error kind with which it \
				has been initially created",
		);
	}

	/// Tests `operation_error::new()` function's happy path.
	#[test]
	fn operation_error_mod_new() {
		operation_error::new(ErrorKind::IncorrectEstablishData);
	}
}
