//! An implementation of paseto v1 "local" tokens, or tokens encrypted using a shared secret.

use crate::errors::GenericError;
use crate::pae::pae;
use crate::v1::get_nonce::calculate_hashed_nonce;
use crate::v1::key_wrapper::CustomKeyWrapper;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use failure::Error;
use openssl::symm;
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::hkdf::{Salt, HKDF_SHA384};
use ring::hmac::{sign, Key, HMAC_SHA384};
use ring::rand::{SecureRandom, SystemRandom};

const HEADER: &str = "v1.local.";

/// Encrypt a "v1.local" paseto token.
///
/// Returns a result of a string if encryption was successful.
pub fn local_paseto(msg: &str, footer: Option<&str>, key: &[u8]) -> Result<String, Error> {
  let rng = SystemRandom::new();
  let mut buff: [u8; 32] = [0u8; 32];
  let res = rng.fill(&mut buff);
  if res.is_err() {
    return Err(GenericError::RandomError {})?;
  }

  underlying_local_paseto(msg, footer, &buff, key)
}

/// Performs the underlying encryption of a paseto token.
///
/// `msg` - The message to encrypt.
/// `footer` - The optional footer.
/// `random_nonce` - The random nonce.
/// `key` - The key used for encryption.
fn underlying_local_paseto(msg: &str, footer: Option<&str>, random_nonce: &[u8], key: &[u8]) -> Result<String, Error> {
  let footer_frd = footer.unwrap_or("");
  let true_nonce = calculate_hashed_nonce(msg.as_bytes(), random_nonce);

  let (as_salt, ctr_nonce) = true_nonce.split_at(16);
  let hkdf_salt = Salt::new(HKDF_SHA384, as_salt);

  let mut ek = [0; 32];
  let mut ak = [0; 32];

  let ek_info = ["paseto-encryption-key".as_bytes()];
  let ak_info = ["paseto-auth-key-for-aead".as_bytes()];

  let extracted = hkdf_salt.extract(key);
  let ek_result = extracted.expand(&ek_info, CustomKeyWrapper(32));
  let ak_result = extracted.expand(&ak_info, CustomKeyWrapper(32));
  if ek_result.is_err() || ak_result.is_err() {
    return Err(GenericError::BadHkdf {})?;
  }
  let ek_fill_result = ek_result.unwrap().fill(&mut ek);
  let ak_fill_result = ak_result.unwrap().fill(&mut ak);
  if ek_fill_result.is_err() || ak_fill_result.is_err() {
    return Err(GenericError::BadHkdf {})?;
  }

  let cipher = symm::Cipher::aes_256_ctr();
  let crypted = symm::encrypt(cipher, &ek, Some(&ctr_nonce), msg.as_bytes())?;

  let pre_auth = pae(&[
    HEADER.as_bytes(),
    &true_nonce,
    &crypted,
    footer_frd.as_bytes(),
  ]);

  let mac_key = Key::new(HMAC_SHA384, &ak);
  let signed = sign(&mac_key, &pre_auth);
  let raw_bytes_from_hmac = signed.as_ref();

  let mut concated_together = Vec::new();
  concated_together.extend_from_slice(&true_nonce);
  concated_together.extend_from_slice(&crypted);
  concated_together.extend_from_slice(&raw_bytes_from_hmac);

  let token = if footer_frd.is_empty() {
    format!("{}{}", HEADER, encode_config(&concated_together, URL_SAFE_NO_PAD))
  } else {
    format!(
      "{}{}.{}",
      HEADER,
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
pub fn decrypt_paseto(token: &str, footer: Option<&str>, key: &[u8]) -> Result<String, Error> {
  let token_parts = token.split(".").collect::<Vec<_>>();
  if token_parts.len() < 3 {
    return Err(GenericError::InvalidToken {})?;
  }

  let is_footer_some = footer.is_some();
  let footer_str = footer.unwrap_or("");

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
  let hkdf_salt = Salt::new(HKDF_SHA384, as_salt);

  let mut ek = [0; 32];
  let mut ak = [0; 32];

  let extracted = hkdf_salt.extract(key);
  let ek_info = ["paseto-encryption-key".as_bytes()];
  let ak_info = ["paseto-auth-key-for-aead".as_bytes()];

  let ek_result = extracted.expand(&ek_info, CustomKeyWrapper(32));
  let ak_result = extracted.expand(&ak_info, CustomKeyWrapper(32));
  if ek_result.is_err() || ak_result.is_err() {
    return Err(GenericError::BadHkdf {})?;
  }
  let ek_fill_result = ek_result.unwrap().fill(&mut ek);
  let ak_fill_result = ak_result.unwrap().fill(&mut ak);
  if ek_fill_result.is_err() || ak_fill_result.is_err() {
    return Err(GenericError::BadHkdf {})?;
  }

  let pre_auth = pae(&[
    HEADER.as_bytes(),
    &nonce,
    ciphertext,
    footer_str.as_bytes(),
  ]);

  let mac_key = Key::new(HMAC_SHA384, &ak);
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
    let message_a = local_paseto("msg", None, &key_buff).expect("Failed to encrypt V1 Paseto string");
    // NOTE: This test is just ensuring we can encode a json object, remember these internal impls
    // don't check for expires being valid!
    let message_b = local_paseto(
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
      None,
      &key_buff,
    )
    .expect("Failed to encrypt V1 Paseto Json BLOB");

    assert!(message_a.starts_with("v1.local."));
    assert!(message_b.starts_with("v1.local."));

    let decrypted_a = decrypt_paseto(&message_a, None, &key_buff).expect("Failed to decrypt V1 Paseto String");
    let decrypted_b = decrypt_paseto(&message_b, None, &key_buff).expect("Failed to decrypt V1 Paseto JSON Blob");

    assert_eq!(decrypted_a, "msg");
    assert_eq!(
      decrypted_b,
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
    );

    let should_fail_decryption_a = decrypt_paseto(&message_a, Some("data"), &key_buff);
    assert!(should_fail_decryption_a.is_err());

    // Try with footers.
    let message_c =
      local_paseto("msg", Some("data"), &key_buff).expect("Failed to encrypt V1 Paseto String with footer!");
    let message_d = local_paseto(
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
      Some("data"),
      &key_buff,
    )
    .expect("Failed to encrypt V1 Paseto Json blob with footer!");

    assert!(message_c.starts_with("v1.local."));
    assert!(message_d.starts_with("v1.local."));

    let decrypted_c =
      decrypt_paseto(&message_c, Some("data"), &key_buff).expect("Failed to decrypt V1 Paseto String with footer!");
    let decrypted_d =
      decrypt_paseto(&message_d, Some("data"), &key_buff).expect("Failed to decrypt V1 Paseto Json Blob with footer!");

    assert_eq!(decrypted_c, "msg");
    assert_eq!(
      decrypted_d,
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
    );

    // Try with no footer + invalid footer.
    let should_fail_decryption_b = decrypt_paseto(&message_c, None, &key_buff);
    let should_fail_decryption_c = decrypt_paseto(&message_c, Some("invalid"), &key_buff);

    assert!(should_fail_decryption_b.is_err());
    assert!(should_fail_decryption_c.is_err());
  }
}
