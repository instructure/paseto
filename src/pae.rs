//! Implements "Pre-Authentication Encoding". Which is part of the Pasesto Specification
//! for version 2 of Paseto.

/// Encodes a u64-bit unsigned integer into a little-endian binary string.
///
/// * `to_encode` - The u8 to encode.
fn le64(mut to_encode: u64) -> Vec<u8> {
  let mut the_vec = Vec::with_capacity(8);

  for _idx in 0..8 {
    the_vec.push((to_encode & 255) as u8);
    to_encode = to_encode >> 8;
  }

  the_vec
}

/// Performs Pre-Authentication Encoding (or PAE) as described in the
/// Paseto Specification v2.
///
/// * `pieces` - The Pieces to concatenate, and encode together.
pub fn pae<'a>(pieces: &'a [&'a [u8]]) -> Vec<u8> {
  let the_vec = le64(pieces.len() as u64);

  pieces.into_iter().fold(the_vec, |mut acc, piece| {
    acc.extend(le64(piece.len() as u64));
    acc.extend(piece.into_iter());
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
      hex::encode(&pae(&[
        "Paragon".as_bytes(),
        "Initiative".as_bytes(),
      ]))
    );
  }
}
