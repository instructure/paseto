//! An Implementation of Paseto V2 "local" tokens (or tokens that are encrypted with a shared secret).

use errors::*;
use pae::pae;
use sodium::aead::{xchacha20poly1305_ietf_decrypt, xchacha20poly1305_ietf_encrypt};
use sodium::hash::crypto_generic_hash;
use sodium::{init_sodium, IS_LIBSODIUM_INTIALIZED};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::rand::{SecureRandom, SystemRandom};

use std::sync::atomic::Ordering;

/// Encrypt a "v2.local" pasesto token.
///
/// Returns a result of a string if encryption was successful.
pub fn local_paseto(msg: String, footer: Option<String>, key: &mut [u8]) -> Result<String> {
  let rng = SystemRandom::new();
  let mut buff: [u8; 24] = [0u8; 24];
  try!(rng.fill(&mut buff));

  underlying_local_paseto(msg, footer, buff, key)
}

/// Performs the underlying encryption of a paseto token. Split for unit testing.
///
/// `msg` - The Msg to Encrypt.
/// `footer` - The footer to add.
/// `nonce_key` - The key to the nonce, should be securely generated.
/// `key` - The key to encrypt the message with.
fn underlying_local_paseto(msg: String, footer: Option<String>, nonce_key: [u8; 24], key: &mut [u8]) -> Result<String> {
  if !IS_LIBSODIUM_INTIALIZED.load(Ordering::Relaxed) {
    if let Err(_e) = init_sodium() {
      return Err(ErrorKind::LibSodiumError.into());
    }
    IS_LIBSODIUM_INTIALIZED.store(true, Ordering::Relaxed);
  }
  let header = String::from("v2.local.");
  let footer_frd = footer.unwrap_or(String::default());
  let nonce = try!(crypto_generic_hash(msg.as_bytes(), Some(&nonce_key), 24 as usize));

  let header_as_vec = Vec::from(header.as_bytes());
  let footer_as_vec = Vec::from(footer_frd.as_bytes());

  let pre_auth = pae(vec![header_as_vec, nonce.clone(), footer_as_vec]);

  let crypted = try!(xchacha20poly1305_ietf_encrypt(
    msg,
    Some(pre_auth),
    nonce.clone().as_mut_slice(),
    key
  ));

  let mut n_and_c = Vec::new();
  n_and_c.extend_from_slice(&nonce);
  n_and_c.extend_from_slice(&crypted);

  let token = if !footer_frd.is_empty() {
    format!(
      "{}{}.{}",
      header,
      encode_config(&n_and_c, URL_SAFE_NO_PAD),
      encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
    )
  } else {
    format!("{}{}", header, encode_config(&n_and_c, URL_SAFE_NO_PAD))
  };

  Ok(token)
}

/// Decrypt a Paseto TOKEN, validating against an optional footer.
///
/// `token`: The Token to decrypt.
/// `footer`: The Optional footer to validate.
/// `key`: The key to decrypt your Paseto.
pub fn decrypt_paseto(token: String, footer: Option<String>, key: &mut [u8]) -> Result<String> {
  if !IS_LIBSODIUM_INTIALIZED.load(Ordering::Relaxed) {
    if let Err(_e) = init_sodium() {
      return Err(ErrorKind::LibSodiumError.into());
    }
    IS_LIBSODIUM_INTIALIZED.store(true, Ordering::Relaxed);
  }
  let token_parts = token.split(".").map(|item| item.to_owned()).collect::<Vec<String>>();
  if token_parts.len() < 3 {
    return Err(ErrorKind::InvalidPasetoToken.into());
  }

  let is_footer_some = footer.is_some();
  let footer_str = footer.unwrap_or(String::default());

  if is_footer_some {
    if token_parts.len() < 4 {
      return Err(ErrorKind::InvalidPasetoFooter.into());
    }
    let as_base64 = encode_config(footer_str.as_bytes(), URL_SAFE_NO_PAD);

    if ConstantTimeEquals(as_base64.as_bytes(), token_parts[3].as_bytes()).is_err() {
      return Err(ErrorKind::InvalidPasetoFooter.into());
    }
  }

  if token_parts[0] != "v2" || token_parts[1] != "local" {
    return Err(ErrorKind::InvalidPasetoToken.into());
  }

  let mut decoded = try!(decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD));
  let (mut nonce, ciphertext) = decoded.split_at_mut(24);
  let mut cloned_nonce = [0; 24];
  cloned_nonce.clone_from_slice(nonce);

  let static_header = Vec::from("v2.local.".as_bytes());
  let vecd_nonce = cloned_nonce.to_vec();
  let vecd_footer = Vec::from(footer_str.as_bytes());
  let pre_auth = pae(vec![static_header, vecd_nonce, vecd_footer]);

  xchacha20poly1305_ietf_decrypt(Vec::from(ciphertext), Some(pre_auth), &mut nonce, key)
}

#[cfg(test)]
mod unit_tests {
  use super::*;

  #[test]
  fn paseto_empty_encrypt_verify() {
    let mut empty_key = [0; 32];
    let mut full_key = [255; 32];
    let result = underlying_local_paseto(String::from(""), None, [0; 24], &mut empty_key);
    if result.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", result);
      panic!("Paseto Failure Encryption!");
    }
    let the_str = result.unwrap();

    assert_eq!(
      "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
      the_str
    );

    let result_full = underlying_local_paseto(String::from(""), None, [0; 24], &mut full_key);
    if result_full.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", result_full);
      panic!("Paseto Failure Encryption!");
    }
    let the_full_str = result_full.unwrap();

    assert_eq!(
      "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
      the_full_str
    );
  }

  #[test]
  fn paseto_non_empty_footer_encrypt_verify() {
    let mut empty_key = [0; 32];
    let mut full_key = [255; 32];

    let result = underlying_local_paseto(
      String::from(""),
      Some(String::from("Cuon Alpinus")),
      [0; 24],
      &mut empty_key,
    );
    if result.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", result);
      panic!("Paseto Failure Encryption!");
    }
    let the_str = result.unwrap();

    assert_eq!(
      "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
      the_str
    );

    let full_result = underlying_local_paseto(
      String::from(""),
      Some(String::from("Cuon Alpinus")),
      [0; 24],
      &mut full_key,
    );
    if full_result.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", full_result);
      panic!("Paseto Failure Encryption!");
    }
    let full_str = full_result.unwrap();

    assert_eq!(
      "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
      full_str
    );
  }

  #[test]
  fn paseto_non_empty_msg_encrypt_verify() {
    let mut empty_key = [0; 32];
    let mut full_key = [255; 32];

    let result = underlying_local_paseto(
      String::from("Love is stronger than hate or fear"),
      None,
      [0; 24],
      &mut empty_key,
    );
    if result.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", result);
      panic!("Paseto Failure Encryption!");
    }
    let the_str = result.unwrap();

    assert_eq!(
      "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
      the_str
    );

    let full_result = underlying_local_paseto(
      String::from("Love is stronger than hate or fear"),
      None,
      [0; 24],
      &mut full_key,
    );
    if full_result.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", full_result);
      panic!("Paseto Failure Encryption!");
    }

    let full_str = full_result.unwrap();

    assert_eq!(
      "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
      full_str
    );
  }

  #[test]
  fn full_round_paseto() {
    let mut empty_key = [0; 32];

    let result = local_paseto(
      String::from("Love is stronger than hate or fear"),
      Some(String::from("gwiz-bot")),
      &mut empty_key,
    );
    if result.is_err() {
      println!("Failed to encrypt Paseto!");
      println!("{:?}", result);
      panic!("Paseto Failure Encryption!");
    }
    let the_str = result.unwrap();

    println!("Paseto Full Round Token: [ {:?} ]", the_str);

    let decrypted_result = decrypt_paseto(the_str, Some(String::from("gwiz-bot")), &mut empty_key);
    if decrypted_result.is_err() {
      println!("Failed to decrypt Paseto!");
      println!("{:?}", decrypted_result);
      panic!("Paseto Failure Decryption!");
    }
    let decrypted = decrypted_result.unwrap();

    assert_eq!(decrypted, "Love is stronger than hate or fear");
  }
}
