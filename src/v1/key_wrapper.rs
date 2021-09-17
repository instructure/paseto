use ring::hkdf;

/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.

// BORROWED FROM RING Itself.
// LICENSE: https://github.com/briansmith/ring/blob/master/LICENSE
pub struct CustomKeyWrapper<T>(pub T);

impl hkdf::KeyType for CustomKeyWrapper<usize> {
	fn len(&self) -> usize {
		self.0
	}
}

impl From<hkdf::Okm<'_, CustomKeyWrapper<usize>>> for CustomKeyWrapper<Vec<u8>> {
	fn from(okm: hkdf::Okm<CustomKeyWrapper<usize>>) -> Self {
		let mut r = vec![0_u8; okm.len().0];
		okm.fill(&mut r).unwrap();
		CustomKeyWrapper(r)
	}
}
