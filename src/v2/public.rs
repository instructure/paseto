//! An implementation of Paseto v2 "public" tokens, or tokens that
//! are signed with a public/private key pair.

use crate::errors::GenericError;
use crate::pae::pae;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use failure::Error;
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::signature::{verify as PubKeyVerify, Ed25519KeyPair, ED25519};
use untrusted::Input as UntrustedInput;

/// Sign a "v2.public" paseto token.
///
/// Returns a result of a string if signing was successful.
pub fn public_paseto(msg: String, footer: Option<String>, key_pair: &Ed25519KeyPair) -> Result<String, Error> {
  let header = String::from("v2.public.");
  let footer_frd = footer.unwrap_or(String::default());

  let pre_auth = pae(vec![
    Vec::from(header.as_bytes()),
    Vec::from(msg.as_bytes()),
    Vec::from(footer_frd.as_bytes()),
  ]);

  let sig = key_pair.sign(&pre_auth);
  let mut m_and_sig = Vec::from(msg.as_bytes());
  m_and_sig.extend_from_slice(sig.as_ref());

  let token = if footer_frd.is_empty() {
    format!("{}{}", header, encode_config(&m_and_sig, URL_SAFE_NO_PAD))
  } else {
    format!(
      "{}{}.{}",
      header,
      encode_config(&m_and_sig, URL_SAFE_NO_PAD),
      encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
    )
  };

  Ok(token)
}

/// Verifies a "v2.public" paseto token based on a given key pair.
///
/// Returns the message if verification was successful, otherwise an Err().
pub fn verify_paseto(token: String, footer: Option<String>, public_key: &[u8]) -> Result<String, Error> {
  let token_parts = token.split(".").map(|item| item.to_owned()).collect::<Vec<String>>();
  if token_parts.len() < 3 {
    return Err(GenericError::InvalidToken {})?;
  }

  let has_provided_footer = footer.is_some();
  let footer_as_str = footer.unwrap_or("".to_owned());

  if has_provided_footer {
    if token_parts.len() < 4 {
      return Err(GenericError::InvalidFooter {})?;
    }
    let footer_encoded = encode_config(footer_as_str.as_bytes(), URL_SAFE_NO_PAD);

    if ConstantTimeEquals(footer_encoded.as_bytes(), token_parts[3].as_bytes()).is_err() {
      return Err(GenericError::InvalidFooter {})?;
    }
  }

  if token_parts[0] != "v2" || token_parts[1] != "public" {
    return Err(GenericError::InvalidToken {})?;
  }

  let decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)?;
  let decoded_len = decoded.len();
  let (msg, sig) = decoded.split_at(decoded_len - 64);

  let pre_auth = pae(vec![
    Vec::from(String::from("v2.public.").as_bytes()),
    Vec::from(msg),
    Vec::from(footer_as_str.as_bytes()),
  ]);

  let pk_as_untrusted = UntrustedInput::from(public_key);
  let sig_as_untrusted = UntrustedInput::from(sig);
  let pae_as_untrusted = UntrustedInput::from(&pre_auth);

  PubKeyVerify(&ED25519, pk_as_untrusted, pae_as_untrusted, sig_as_untrusted)?;

  Ok(String::from_utf8(Vec::from(msg))?)
}

#[cfg(test)]
mod unit_tests {
  use super::*;

  use ring::rand::SystemRandom;
  use ring::signature::KeyPair;

  #[test]
  fn paseto_public_verify() {
    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_untrusted = UntrustedInput::from(key_pkcs8.as_ref());
    let as_key = Ed25519KeyPair::from_pkcs8(as_untrusted).expect("Failed to parse keypair");

    // Test messages without footers.
    let public_token_one =
      public_paseto(String::from("msg"), None, &as_key).expect("Failed to public encode msg with no footer!");
    // NOTE: This test is just ensuring we can encode a json object, remember these internal impls
    // don't check for expires being valid!
    let public_token_two = public_paseto(
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"),
      None,
      &as_key,
    )
    .expect("Failed to public encode json blob with no footer!");

    assert!(public_token_one.starts_with("v2.public."));
    assert!(public_token_two.starts_with("v2.public."));

    let verified_one = verify_paseto(public_token_one.clone(), None, as_key.public_key().as_ref());
    let verified_two = verify_paseto(public_token_two, None, as_key.public_key().as_ref());

    // Verify the above tokens.
    assert!(verified_one.is_ok());
    assert!(verified_two.is_ok());
    assert_eq!(verified_one.unwrap(), String::from("msg"));
    assert_eq!(
      verified_two.unwrap(),
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}")
    );

    let should_not_verify_one = verify_paseto(
      public_token_one,
      Some(String::from("data")),
      as_key.public_key().as_ref(),
    );

    // Verify if it doesn't have a footer in public that it won't pass a verification with a footer.
    assert!(should_not_verify_one.is_err());

    // Now lets verify with footers.
    let public_token_three = public_paseto(String::from("msg"), Some(String::from("footer")), &as_key)
      .expect("Failed to public encode msg with footer!");
    let public_token_four = public_paseto(
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"),
      Some(String::from("footer")),
      &as_key,
    )
    .expect("Failed to public encode json blob with footer!");

    assert!(public_token_three.starts_with("v2.public."));
    assert!(public_token_four.starts_with("v2.public."));

    let verified_three = verify_paseto(
      public_token_three.clone(),
      Some(String::from("footer")),
      as_key.public_key().as_ref(),
    );
    let verified_four = verify_paseto(
      public_token_four,
      Some(String::from("footer")),
      as_key.public_key().as_ref(),
    );

    // Verify the footer tokens.
    assert!(verified_three.is_ok());
    assert!(verified_four.is_ok());
    assert_eq!(verified_three.unwrap(), String::from("msg"));
    assert_eq!(
      verified_four.unwrap(),
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}")
    );

    // Validate no footer + invalid footer both fail on tokens encode with footer.
    let should_not_verify_two = verify_paseto(public_token_three.clone(), None, as_key.public_key().as_ref());
    let should_not_verify_three = verify_paseto(
      public_token_three,
      Some(String::from("bleh")),
      as_key.public_key().as_ref(),
    );

    assert!(should_not_verify_two.is_err());
    assert!(should_not_verify_three.is_err());
  }
}
