use crate::secret::Error;

pub trait CommunicationKey {
	fn name(&self) -> String;
	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
	/// Decrypts `encrypted_data`.
	/// # Parameters
	/// * `encrypted_data` &ndash; The data to be decrypted.
	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
	/// Returns the&nbsp;stored encryption key representation as raw bytes.
	fn bytes(&self) -> Vec<u8>;
}
