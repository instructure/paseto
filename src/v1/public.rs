//! An implementation of Paseto v1 "public" tokens, or tokens that
//! are signed with a public/private key pair.

use crate::errors::{GenericError, RsaKeyErrors};
use crate::pae::pae;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use failure::Error;
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, UnparsedPublicKey, RSA_PSS_2048_8192_SHA384, RSA_PSS_SHA384};

/// Sign a "v1.public" paseto token.
///
/// Returns a result of a string if signing was successful.
pub fn public_paseto(msg: &str, footer: Option<String>, key_pair: &mut RsaKeyPair) -> Result<String, Error> {
  if key_pair.public_modulus_len() != 256 {
    return Err(RsaKeyErrors::InvalidKey {})?;
  }
  let footer_frd = footer.unwrap_or(String::default());

  let header = String::from("v1.public.");
  let pre_auth = pae(vec![
    Vec::from(header.as_bytes()),
    Vec::from(msg.as_bytes()),
    Vec::from(footer_frd.as_bytes()),
  ]);
  let random = SystemRandom::new();

  let mut signed_msg = [0; 256];
  let sign_res = key_pair.sign(&RSA_PSS_SHA384, &random, &pre_auth, &mut signed_msg);
  if sign_res.is_err() {
    return Err(RsaKeyErrors::SignError {})?;
  }

  let mut combined_vec = Vec::new();
  combined_vec.extend_from_slice(msg.as_bytes());
  combined_vec.extend_from_slice(&signed_msg);

  let token = if footer_frd.is_empty() {
    format!("{}{}", header, encode_config(&combined_vec, URL_SAFE_NO_PAD))
  } else {
    format!(
      "{}{}.{}",
      header,
      encode_config(&combined_vec, URL_SAFE_NO_PAD),
      encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
    )
  };

  Ok(token)
}

/// Verifies a "v1.public" paseto token based on a public key
///
/// Returns the message if verification was successful, otherwise an Err().
pub fn verify_paseto(token: &str, footer: Option<String>, public_key: &[u8]) -> Result<String, Error> {
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

  if token_parts[0] != "v1" || token_parts[1] != "public" {
    return Err(GenericError::InvalidToken {})?;
  }

  let decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)?;
  let decoded_len = decoded.len();
  let (message, sig) = decoded.split_at(decoded_len - 256);

  let pre_auth = pae(vec![
    Vec::from("v1.public.".as_bytes()),
    Vec::from(message),
    Vec::from(footer_as_str.as_bytes()),
  ]);

  let pk_unparsed = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, public_key);
  let verify_result = pk_unparsed.verify(&pre_auth, sig);
  if verify_result.is_err() {
    return Err(GenericError::InvalidToken {})?;
  }

  Ok(String::from_utf8(Vec::from(message))?)
}

#[cfg(test)]
mod unit_tests {
  use super::*;

  use ring::signature::RsaKeyPair;

  #[test]
  fn test_v1_public() {
    let private_key = include_bytes!("signature_rsa_example_private_key.der");
    let public_key = include_bytes!("signature_rsa_example_public_key.der");

    let mut key_pair = RsaKeyPair::from_der(private_key).expect("Bad Private Key pkcs!");

    // Test keys without footers.
    let public_token_one =
      public_paseto("msg", None, &mut key_pair).expect("Failed to encode public paseto v1 msg with no footer!");
    // Remember raw protocol doesn't validate expires. We're just ensuring we can encode it.
    let public_token_two = public_paseto(
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
      None,
      &mut key_pair,
    )
    .expect("Failed to encode public paseto v1 json blob with no footer!");

    let verified_one = verify_paseto(&public_token_one, None, public_key)
      .expect("Failed to verify public paseto v1 msg with no footer!");
    let verified_two = verify_paseto(&public_token_two, None, public_key)
      .expect("Failed to verify public paseto v1 json blob with no footer!");

    assert_eq!(verified_one, String::from("msg"));
    assert_eq!(
      verified_two,
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}")
    );

    // Attempt to verify with a footer
    let should_not_verify_one = verify_paseto(&public_token_one, Some(String::from("hoi")), public_key);
    assert!(should_not_verify_one.is_err());

    let public_token_three = public_paseto("msg", Some(String::from("data")), &mut key_pair)
      .expect("Failed to encode public paseto v1 msg with footer!");
    let public_token_four = public_paseto(
      "{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
      Some(String::from("data")),
      &mut key_pair,
    )
    .expect("Failed to encode public paseto v1 json blob with footer!");

    let verified_three = verify_paseto(&public_token_three, Some(String::from("data")), public_key)
      .expect("Failed to verify public paseto v1 msg with footer!");
    let verified_four = verify_paseto(&public_token_four, Some(String::from("data")), public_key)
      .expect("Failed to verify public paseto v1 json blob with footer!");

    assert_eq!(verified_three, String::from("msg"));
    assert_eq!(
      verified_four,
      String::from("{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}")
    );

    // Ensure that no footer + incorrect footer fail to validate.
    let should_not_verify_two = verify_paseto(&public_token_three, None, public_key);
    let should_not_verify_three = verify_paseto(&public_token_three, Some(String::from("test")), public_key);

    assert!(should_not_verify_two.is_err());
    assert!(should_not_verify_three.is_err());
  }
}
