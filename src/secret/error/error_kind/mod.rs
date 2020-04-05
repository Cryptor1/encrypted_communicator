/// Type of error occurred while performing actions over encryption key.
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorKind {
	/// Obtaining a&nbsp;random generation sequence is blocked on
	/// the&nbsp;operating system level. Usually this happens when
	/// a&nbsp;[Cryptographically secure pseudorandom number generator (CSPRNG)][1]
	/// has&nbsp;not&nbsp;been&nbsp;seeded yet.
	///
	/// [1]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
	GenerationBlocked,
	GenerationFailed(Option<String>),
	EncryptionFailed(Option<String>),
	DecryptionFailed(Option<String>),
	/// Failure due to an&nbsp;attempt to generate inappropriate key.
	IncorrectKey,
	/// Incorrectly formatted/encrypted data has been passed for decryption.
	IncorrectData,
}
