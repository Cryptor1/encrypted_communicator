use crate::secret::Error;

pub trait NegotiationKey {
	fn name(&self) -> String;
	fn has_private(&self) -> bool;
	fn has_public(&self) -> bool;
	fn decrypt_with_private(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
	fn encrypt_with_public(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
	fn private_part(&self) -> Vec<u8>;
	fn public_part(&self) -> Vec<u8>;
}
