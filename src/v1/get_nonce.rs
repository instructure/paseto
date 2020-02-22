//! An implementation of "get_nonce" for version one of paseto tokens.

use ring::hmac::{sign, Key, HMAC_SHA384};

/// An implementation of "get_nonce" from the docs in paseto version one.
///
/// This function is to ensure that an RNG failure does not result in a
/// nonce-misuse condition that breaks the security of our stream cipher.
pub fn calculate_hashed_nonce(msg: &[u8], random_nonce: &[u8]) -> Vec<u8> {
  let mac_key = Key::new(HMAC_SHA384, random_nonce);
  let signed = sign(&mac_key, msg);
  Vec::from(&signed.as_ref()[0..32])
}

#[cfg(test)]
mod unit_tests {
  use super::*;
  use hex;

  #[test]
  fn test_nonce_derivation() {
    // Constants copied directly from paseto source.
    let msg_a = "The quick brown fox jumped over the lazy dog.";
    let msg_b = "The quick brown fox jumped over the lazy dof.";
    let nonce = hex::decode("808182838485868788898a8b8c8d8e8f").expect("Failed to decode nonce!");

    let calculated_nonce_a = calculate_hashed_nonce(msg_a.as_bytes(), &nonce);
    let calculated_nonce_b = calculate_hashed_nonce(msg_b.as_bytes(), &nonce);

    assert_eq!(
      "5e13b4f0fc111bf0cf9de4e97310b687858b51547e125790513cc1eaaef173cc",
      hex::encode(&calculated_nonce_a)
    );
    assert_eq!(
      "e1ba992f5cccd31714fd8c73adcdadabb00d0f23955a66907170c10072d66ffd",
      hex::encode(&calculated_nonce_b)
    )
  }
}
