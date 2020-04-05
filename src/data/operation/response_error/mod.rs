/// Error type related to `Operation::Response`.
#[derive(Debug, PartialEq)]
pub enum ResponseErrorType {
	/// Encrypted connection has been already established previously.
	AlreadyEstablished,
}

/// Determines `ResponseErrorType` based on a&nbsp;given `error` string slice.
pub fn define_error_type(error: &str) -> Result<ResponseErrorType, Error> {
	return match error {
		"already established" => Ok(ResponseErrorType::AlreadyEstablished),
		_ => Err(Error{}),
	}
}

/// Returns response error type in a&nbsp;string representation.
pub fn define_error_type_as_string(error: ResponseErrorType) -> String {
	return match error {
		ResponseErrorType::AlreadyEstablished => "already established".to_owned(),
	}
}

/// Denotes error while determining `ResponseErrorType` from string using
/// `define_error_type()`.
#[derive(Debug)]
pub struct Error {}

#[cfg(test)]
mod tests {
	use crate::data::operation::response_error;
	use crate::data::ResponseErrorType;

	/// Tests `response_error::define_error_type()` function's happy path.
	#[test]
	fn response_error_mod_define_error_type() {
		let response: ResponseErrorType =
			response_error::define_error_type("already established")
				.expect("Should have successfully processed response error type");
		assert_eq!(
			ResponseErrorType::AlreadyEstablished,
			response,
			"Determined error response type is incorrect",
		);
	}

	/// Tests `response_error::define_error_type()` function's error path.
	/// Passes nonexistent error type as `error` argument.
	#[test]
	fn response_error_mod_define_error_type_incorrect_error() {
		response_error::define_error_type("incorrect error literal")
			.expect_err(
				"Should have returned error while processing nonexistent error type",
			);
	}

	/// Tests `response_error::define_error_type_as_string()` function's happy
	/// path.
	#[test]
	fn response_error_mod_define_error_type_as_string() {
		let expected_already_established_error_literal: String =
			String::from("already established");
		let actual_already_established_error_literal: String =
			response_error::define_error_type_as_string(
				ResponseErrorType::AlreadyEstablished,
			);
		assert_eq!(
			expected_already_established_error_literal,
			actual_already_established_error_literal,
			"Incorrect string representation for `{:?}` error type has been returned",
			ResponseErrorType::AlreadyEstablished,
		);
	}
}
