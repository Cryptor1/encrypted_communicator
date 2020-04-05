/// RSA key size variations.
#[derive(Copy, Clone, Debug)]
pub enum RsaKeySize {
	/// Key size of 1024 bits.
	Rsa1024,
	/// Key size of 2048 bits.
	Rsa2048,
	/// Key size of 4096 bits.
	Rsa4096,
}

/// Returns the&nbsp;size in bits a&nbsp;given enum value represents.
pub fn in_bits(key_size: RsaKeySize) -> u32 {
	return match key_size {
		RsaKeySize::Rsa1024 => 1024,
		RsaKeySize::Rsa2048 => 2048,
		RsaKeySize::Rsa4096 => 4096,
	}
}

#[cfg(test)]
mod tests {
	use crate::secret::rsa::{key_size, RsaKeySize};

	/// Tests `key_size::in_bits()` function's happy path.
	#[test]
	fn key_size_mod_in_bits() {
		assert_eq!(
			1024,
			key_size::in_bits(RsaKeySize::Rsa1024),
			"Incorrect key size calculated for 1024-bit key",
		);
		assert_eq!(
			2048,
			key_size::in_bits(RsaKeySize::Rsa2048),
			"Incorrect key size calculated for 2048-bit key",
		);
		assert_eq!(
			4096,
			key_size::in_bits(RsaKeySize::Rsa4096),
			"Incorrect key size calculated for 4096-bit key",
		);
	}
}
