//! Provides a "nice" wrapper around paseto tokens in order to check things such as "Expiration".
//! Issuer, etc.

use crate::errors::GenericError;

#[cfg(feature = "v1")]
use crate::v1::{decrypt_paseto as V1Decrypt, verify_paseto as V1Verify};
#[cfg(feature = "v2")]
use crate::v2::{decrypt_paseto as V2Decrypt, verify_paseto as V2Verify};

use chrono::prelude::*;
use failure::Error;
#[cfg(feature = "v2")]
use ring::signature::Ed25519KeyPair;
use ring::signature::KeyPair;
use serde_json::{from_str as ParseJson, Value as JsonValue};

pub mod builder;
pub use self::builder::*;

/// Wraps the two paseto public key types so we can just have a "validate_public_token"
/// method without splitting the two implementations.
pub enum PasetoPublicKey {
  #[cfg(feature = "v1")]
  RSAPublicKey(Vec<u8>),
  #[cfg(feature = "v2")]
  ED25519KeyPair(Ed25519KeyPair),
  #[cfg(feature = "v2")]
  ED25519PublicKey(Vec<u8>),
}

/// Validates a potential json data blob, returning a JsonValue.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
pub fn validate_potential_json_blob(data: &str) -> Result<JsonValue, Error> {
  let value: JsonValue = ParseJson(data)?;

  let validation = {
    let issued_at_opt = value.get("iat");
    let expired_opt = value.get("exp");
    let not_before_opt = value.get("nbf");

    if let Some(issued_at) = issued_at_opt {
      if let Some(iat) = issued_at.as_str() {
        if let Ok(parsed_iat) = iat.parse::<DateTime<Utc>>() {
          if parsed_iat > Utc::now() {
            return Err(GenericError::InvalidToken {})?;
          }
        } else {
          return Err(GenericError::InvalidToken {})?;
        }
      } else {
        return Err(GenericError::InvalidToken {})?;
      }
    }

    if let Some(expired) = expired_opt {
      if let Some(exp) = expired.as_str() {
        if let Ok(parsed_exp) = exp.parse::<DateTime<Utc>>() {
          if parsed_exp < Utc::now() {
            return Err(GenericError::InvalidToken {})?;
          }
        } else {
          return Err(GenericError::InvalidToken {})?;
        }
      } else {
        return Err(GenericError::InvalidToken {})?;
      }
    }

    if let Some(not_before) = not_before_opt {
      if let Some(nbf) = not_before.as_str() {
        if let Ok(parsed_nbf) = nbf.parse::<DateTime<Utc>>() {
          if parsed_nbf > Utc::now() {
            return Err(GenericError::InvalidToken {})?;
          }
        } else {
          return Err(GenericError::InvalidToken {})?;
        }
      } else {
        return Err(GenericError::InvalidToken {})?;
      }
    }

    Ok(())
  };

  if validation.is_err() {
    validation.err().unwrap()
  } else {
    Ok(value)
  }
}

/// Validate a local token for V1, or V2.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
#[cfg(all(feature = "v1", feature = "v2"))]
pub fn validate_local_token(token: &str, footer: Option<&str>, key: Vec<u8>) -> Result<JsonValue, Error> {
  if token.starts_with("v2.local.") {
    let message = V2Decrypt(token, footer, &key)?;
    return validate_potential_json_blob(&message);
  } else if token.starts_with("v1.local.") {
    let message = V1Decrypt(token, footer, &key)?;
    return validate_potential_json_blob(&message);
  }

  return Err(GenericError::InvalidToken {})?;
}

/// Validate a local token for V1.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
#[cfg(all(feature = "v1", not(feature = "v2")))]
pub fn validate_local_token(token: &str, footer: Option<&str>, key: &Vec<u8>) -> Result<Jsonvalue, Error> {
  let token = V1Decrypt(token, footer, key)?;
  return validate_potential_json_blob(token);
}

/// Validate a local token for V2.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
#[cfg(all(feature = "v2", not(feature = "v1")))]
pub fn validate_local_token(token: &str, footer: Option<&str>, key: &Vec<u8>) -> Result<Jsonvalue, Error> {
  let token = V2Decrypt(token, footer, key)?;
  return validate_potential_json_blob(token);
}

/// Validate a public token for V1, or V2.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
pub fn validate_public_token(token: &str, footer: Option<&str>, key: &PasetoPublicKey) -> Result<JsonValue, Error> {
  if token.starts_with("v2.public.") {
    return match key {
      PasetoPublicKey::ED25519KeyPair(key_pair) => {
        let internal_msg = V2Verify(token, footer, key_pair.public_key().as_ref())?;
        validate_potential_json_blob(&internal_msg)
      }
      PasetoPublicKey::ED25519PublicKey(pub_key_contents) => {
        let internal_msg = V2Verify(token, footer, &pub_key_contents)?;
        validate_potential_json_blob(&internal_msg)
      }
      _ => Err(GenericError::NoKeyProvided {})?,
    };
  } else if token.starts_with("v1.public.") {
    return match key {
      PasetoPublicKey::RSAPublicKey(key_content) => {
        let internal_msg = V1Verify(token, footer, &key_content)?;
        validate_potential_json_blob(&internal_msg)
      }
      _ => Err(GenericError::NoKeyProvided {})?,
    };
  }

  return Err(GenericError::InvalidToken {})?;
}

/// Validate a public token for V1.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
#[cfg(all(feature = "v1", not(feature = "v2")))]
pub fn validate_public_token(token: &str, footer: Option<&str>, key: &PasetoPublicKey) -> Result<Jsonvalue, Error> {
  return match key {
    PasetoPublicKey::RSAPublicKey(key_content) => {
      let internal_msg = V1Verify(token, footer, &key_content)?;
      validate_potential_json_blob(internal_msg)
    }
    _ => Err(GenericError::NoKeyProvided {})?,
  };
}

/// Validate a public token for V2.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
#[cfg(all(feature = "v2", not(feature = "v1")))]
pub fn validate_public_token(token: String, footer: Option<&str>, key: PasetoPublicKey) -> Result<Jsonvalue, Error> {
  return match key {
    PasetoPublicKey::ED25519KeyPair(key_pair) => {
      let internal_msg = V2Verify(token, footer, &key_pair)?;
      validate_potential_json_blob(internal_msg)
    }
    _ => Err(GenericError::NoKeyProvided {})?,
  };
}

#[cfg(test)]
mod unit_tests {
  use super::*;

  use ring::rand::SystemRandom;
  use serde_json::json;

  #[test]
  fn valid_enc_token_passes_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let token = PasetoBuilder::new()
      .set_encryption_key(Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(dt)
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(String::from("data")))
      .set_footer(String::from("footer"))
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    validate_local_token(
      &token,
      Some("footer"),
      Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()),
    )
    .expect("Failed to validate token!");
  }

  #[test]
  fn invalid_enc_token_doesnt_validate() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let token = PasetoBuilder::new()
      .set_encryption_key(Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(dt)
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(String::from("data")))
      .set_footer(String::from("footer"))
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    assert!(validate_local_token(
      &token,
      Some("footer"),
      Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes())
    )
    .is_err());
  }

  #[test]
  fn valid_pub_token_passes_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
    let cloned_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = PasetoBuilder::new()
      .set_ed25519_key(as_key)
      .set_issued_at(None)
      .set_expiration(dt)
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(String::from("data")))
      .set_footer(String::from("footer"))
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    validate_public_token(&token, Some("footer"), &PasetoPublicKey::ED25519KeyPair(cloned_key))
      .expect("Failed to validate token!");
  }

  #[test]
  fn validate_pub_key_only_v2() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
    let cloned_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = PasetoBuilder::new()
      .set_ed25519_key(as_key)
      .set_issued_at(None)
      .set_expiration(dt)
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(String::from("data")))
      .set_footer(String::from("footer"))
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    validate_public_token(
      &token,
      Some("footer"),
      &PasetoPublicKey::ED25519PublicKey(Vec::from(cloned_key.public_key().as_ref())),
    )
    .expect("Failed to validate token!");
  }

  #[test]
  fn invalid_pub_token_doesnt_validate() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
    let cloned_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = PasetoBuilder::new()
      .set_ed25519_key(as_key)
      .set_issued_at(None)
      .set_expiration(dt)
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(String::from("data")))
      .set_footer(String::from("footer"))
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    assert!(validate_public_token(&token, Some("footer"), &PasetoPublicKey::ED25519KeyPair(cloned_key)).is_err());
  }
}
