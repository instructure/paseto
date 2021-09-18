//! Implements "Pre-Authentication Encoding". An encoding scheme unique to
//! paseto. Generally not useful outside of this crate.
//!
//! Pre-Authentication Encoding is an encoding mechanism meant to help
//! prevent canonicalization attacks for local tokens in the additional
//! data field. For more information see:
//! <https://github.com/paseto-standard/paseto-spec/blob/8b3fed8240e203b058649d01a82a8c412087bc87/docs/01-Protocol-Versions/Common.md#authentication-padding>

/// Performs little endian encoding of an unsigned 64 bit integer.
#[allow(clippy::cast_possible_truncation)]
fn le64(mut to_encode: u64) -> Vec<u8> {
	let mut the_vec = Vec::with_capacity(8);

	for _idx in 0..8 {
		the_vec.push((to_encode & 255) as u8);
		to_encode >>= 8;
	}

	the_vec
}

/// Performs the actual pre authentication encoding for a list of binary
/// strings.
#[must_use]
pub fn pae(pieces: &[&[u8]]) -> Vec<u8> {
	let the_vec = le64(pieces.len() as u64);

	pieces.iter().fold(the_vec, |mut acc, piece| {
		acc.extend(le64(piece.len() as u64));
		acc.extend(piece.iter());
		acc
	})
}

#[cfg(test)]
mod unit_tests {
	use super::*;
	use hex;

	#[test]
	fn test_le64() {
		assert_eq!(vec![0, 0, 0, 0, 0, 0, 0, 0], le64(0));
		assert_eq!(vec![10, 0, 0, 0, 0, 0, 0, 0], le64(10));
	}

	#[test]
	fn test_pae() {
		// Constants taken from paseto source.
		assert_eq!("0000000000000000", hex::encode(&pae(&[])));
		assert_eq!(
			"01000000000000000000000000000000",
			hex::encode(&pae(&[&[]]))
		);
		assert_eq!(
			"020000000000000000000000000000000000000000000000",
			hex::encode(&pae(&[&[], &[]]))
		);
		assert_eq!(
			"0100000000000000070000000000000050617261676f6e",
			hex::encode(&pae(&["Paragon".as_bytes()]))
		);
		assert_eq!(
			"0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
			hex::encode(&pae(&["Paragon".as_bytes(), "Initiative".as_bytes(),]))
		);
	}
}
