//! An implementation of paseto v1 "local" tokens, or tokens encrypted using a shared secret.

use crate::errors::GenericError;
use crate::pae::pae;
use crate::v1::get_nonce::calculate_hashed_nonce;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use failure::Error;
use openssl::symm;
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::digest::SHA384;
use ring::hkdf::extract_and_expand as HKDF;
use ring::hmac::{sign, SigningKey};
use ring::rand::{SecureRandom, SystemRandom};

/// Encrypt a "v1.local" paseto token.
///
/// Returns a result of a string if encryption was successful.
pub fn local_paseto(msg: String, footer: Option<String>, key: &[u8]) -> Result<String, Error> {
  let rng = SystemRandom::new();
  let mut buff: [u8; 32] = [0u8; 32];
  rng.fill(&mut buff)?;

  underlying_local_paseto(msg, footer, &buff, key)
}

/// Performs the underlying encryption of a paseto token.
///
/// `msg` - The message to encrypt.
/// `footer` - The optional footer.
/// `random_nonce` - The random nonce.
/// `key` - The key used for encryption.
fn underlying_local_paseto(
  msg: String,
  footer: Option<String>,
  random_nonce: &[u8],
  key: &[u8],
) -> Result<String, Error> {
  let header = String::from("v1.local.");
  let footer_frd = footer.unwrap_or(String::default());
  let true_nonce = calculate_hashed_nonce(msg.as_bytes(), random_nonce);

  let (as_salt, ctr_nonce) = true_nonce.split_at(16);
  let hkdf_salt = SigningKey::new(&SHA384, as_salt);

  let mut ek = [0; 32];
  let mut ak = [0; 32];
  HKDF(&hkdf_salt, key, "paseto-encryption-key".as_bytes(), &mut ek);
  HKDF(&hkdf_salt, key, "paseto-auth-key-for-aead".as_bytes(), &mut ak);

  let cipher = symm::Cipher::aes_256_ctr();
  let crypted = symm::encrypt(cipher, &ek, Some(&ctr_nonce), msg.as_bytes())?;

  let pre_auth = pae(vec![
    Vec::from(header.as_bytes()),
    true_nonce.clone(),
    crypted.clone(),
    Vec::from(footer_frd.as_bytes()),
  ]);

  let mac_key = SigningKey::new(&SHA384, &ak);
  let signed = sign(&mac_key, &pre_auth);
  let raw_bytes_from_hmac = signed.as_ref();

  let mut concated_together = Vec::new();
  concated_together.extend_from_slice(&true_nonce);
  concated_together.extend_from_slice(&crypted);
  concated_together.extend_from_slice(&raw_bytes_from_hmac);

  let token = if footer_frd.is_empty() {
    format!("{}{}", header, encode_config(&concated_together, URL_SAFE_NO_PAD))
  } else {
    format!(
      "{}{}.{}",
      header,
      encode_config(&concated_together, URL_SAFE_NO_PAD),
      encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
    )
  };

  Ok(token)
}

/// Decrypt a version 1 paseto token.
///
/// `token` - The encrypted token.
/// `footer` - The optional footer to validate against.
/// `key` - The key used to encrypt the token.
pub fn decrypt_paseto(token: String, footer: Option<String>, key: &[u8]) -> Result<String, Error> {
  let token_parts = token.split(".").map(|item| item.to_owned()).collect::<Vec<String>>();
  if token_parts.len() < 3 {
    return Err(GenericError::InvalidToken {})?;
  }

  let is_footer_some = footer.is_some();
  let footer_str = footer.unwrap_or(String::default());

  if is_footer_some {
    if token_parts.len() < 4 {
      return Err(GenericError::InvalidFooter {})?;
    }
    let as_base64 = encode_config(footer_str.as_bytes(), URL_SAFE_NO_PAD);

    if ConstantTimeEquals(as_base64.as_bytes(), token_parts[3].as_bytes()).is_err() {
      return Err(GenericError::InvalidFooter {})?;
    }
  }

  if token_parts[0] != "v1" || token_parts[1] != "local" {
    return Err(GenericError::InvalidToken {})?;
  }
  let decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)?;
  let (nonce, t_and_c) = decoded.split_at(32);
  // NLL :shakefists:
  let t_and_c_vec = Vec::from(t_and_c);
  let t_and_c_len = t_and_c_vec.len();
  let (ciphertext, mac) = t_and_c_vec.split_at(t_and_c_len - 48);

  let nonce = Vec::from(nonce);
  let (as_salt, ctr_nonce) = nonce.split_at(16);

  let mut ek = [0; 32];
  let mut ak = [0; 32];
  let hkdf_salt = SigningKey::new(&SHA384, as_salt);
  HKDF(&hkdf_salt, key, "paseto-encryption-key".as_bytes(), &mut ek);
  HKDF(&hkdf_salt, key, "paseto-auth-key-for-aead".as_bytes(), &mut ak);

  let pre_auth = pae(vec![
    Vec::from("v1.local.".as_bytes()),
    nonce.clone(),
    Vec::from(ciphertext),
    Vec::from(footer_str.as_bytes()),
  ]);

  let mac_key = SigningKey::new(&SHA384, &ak);
  let signed = sign(&mac_key, &pre_auth);
  let raw_bytes_from_hmac = signed.as_ref();

  if ConstantTimeEquals(&raw_bytes_from_hmac, mac).is_err() {
    return Err(GenericError::InvalidToken {})?;
  }

  let cipher = symm::Cipher::aes_256_ctr();
  let decrypted = symm::decrypt(cipher, &ek, Some(ctr_nonce), ciphertext)?;

  Ok(String::from_utf8(decrypted)?)
}

#[cfg(test)]
mod unit_tests {
  use super::*;
  use ring::rand::{SecureRandom, SystemRandom};

  #[test]
  fn test_v1_local() {
    let rng = SystemRandom::new();
    let mut key_buff: [u8; 32] = [0u8; 32];
    rng.fill(&mut key_buff).expect("Failed to fill key_buff!");

    // Try to encrypt without footers.
    let message_a = local_paseto(String::from("msg"), None, &key_buff).expect("Failed to encrypt V1 Paseto string");
    // NOTE: This test is just ensuring we can encode a json object, remember these internal impls
    // don't check for expires being valid!
    let message_b = local_paseto(
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"),
      None,
      &key_buff,
    )
    .expect("Failed to encrypt V1 Paseto Json BLOB");

    assert!(message_a.starts_with("v1.local."));
    assert!(message_b.starts_with("v1.local."));

    let decrypted_a = decrypt_paseto(message_a.clone(), None, &key_buff).expect("Failed to decrypt V1 Paseto String");
    let decrypted_b = decrypt_paseto(message_b, None, &key_buff).expect("Failed to decrypt V1 Paseto JSON Blob");

    assert_eq!(decrypted_a, String::from("msg"));
    assert_eq!(
      decrypted_b,
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}")
    );

    let should_fail_decryption_a = decrypt_paseto(message_a, Some(String::from("data")), &key_buff);
    assert!(should_fail_decryption_a.is_err());

    // Try with footers.
    let message_c = local_paseto(String::from("msg"), Some(String::from("data")), &key_buff)
      .expect("Failed to encrypt V1 Paseto String with footer!");
    let message_d = local_paseto(
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"),
      Some(String::from("data")),
      &key_buff,
    )
    .expect("Failed to encrypt V1 Paseto Json blob with footer!");

    assert!(message_c.starts_with("v1.local."));
    assert!(message_d.starts_with("v1.local."));

    let decrypted_c = decrypt_paseto(message_c.clone(), Some(String::from("data")), &key_buff)
      .expect("Failed to decrypt V1 Paseto String with footer!");
    let decrypted_d = decrypt_paseto(message_d, Some(String::from("data")), &key_buff)
      .expect("Failed to decrypt V1 Paseto Json Blob with footer!");

    assert_eq!(decrypted_c, "msg");
    assert_eq!(
      decrypted_d,
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
    );

    // Try with no footer + invalid footer.
    let should_fail_decryption_b = decrypt_paseto(message_c.clone(), None, &key_buff);
    let should_fail_decryption_c = decrypt_paseto(message_c, Some(String::from("invalid")), &key_buff);

    assert!(should_fail_decryption_b.is_err());
    assert!(should_fail_decryption_c.is_err());
  }
}
