//! Provides a "nice" wrapper around paseto tokens in order to check things such as "Expiration".
//! Issuer, etc.

use errors::*;
#[cfg(feature = "v1")]
use v1::{decrypt_paseto as V1Decrypt, verify_paseto as V1Verify};
#[cfg(feature = "v2")]
use v2::{decrypt_paseto as V2Decrypt, verify_paseto as V2Verify};

use chrono::prelude::*;
#[cfg(feature = "v2")]
use ring::signature::Ed25519KeyPair;
use serde_json::{Value as JsonValue, from_str as ParseJson};

pub mod builder;
pub use builder::*;

/// Wraps the two paseto public key types so we can just have a "validate_public_token"
/// method without splitting the two implementations.
pub enum PasetoPublicKey {
  #[cfg(feature = "v1")]
  RSAPublicKey(Vec<u8>),
  #[cfg(feature = "v2")]
  ED25519KeyPair(Ed25519KeyPair),
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
fn validate_potential_json_blob(data: String) -> Result<JsonValue> {
  let value = ParseJson(&data);
  if value.is_err() {
    return Err(ErrorKind::JsonError.into());
  }
  let value: JsonValue = value.unwrap();

  let validation = {
    let issued_at_opt = value.get("iat");
    let expired_opt = value.get("exp");
    let not_before_opt = value.get("nbf");

    if let Some(issued_at) = issued_at_opt {
      if let Some(iat) = issued_at.as_str() {
        if let Ok(parsed_iat) = iat.parse::<DateTime<Utc>>() {
          if parsed_iat > Utc::now() {
            return Err(ErrorKind::InvalidPasetoToken.into());
          }
        } else {
          return Err(ErrorKind::InvalidPasetoToken.into());
        }
      } else {
        return Err(ErrorKind::InvalidPasetoToken.into());
      }
    }

    if let Some(expired) = expired_opt {
      if let Some(exp) = expired.as_str() {
        if let Ok(parsed_exp) = exp.parse::<DateTime<Utc>>() {
          if parsed_exp < Utc::now() {
            return Err(ErrorKind::InvalidPasetoToken.into());
          }
        } else {
          return Err(ErrorKind::InvalidPasetoToken.into());
        }
      } else {
        return Err(ErrorKind::InvalidPasetoToken.into());
      }
    }

    if let Some(not_before) = not_before_opt {
      if let Some(nbf) = not_before.as_str() {
        if let Ok(parsed_nbf) = nbf.parse::<DateTime<Utc>>() {
          if parsed_nbf > Utc::now() {
            return Err(ErrorKind::InvalidPasetoToken.into());
          }
        } else {
          return Err(ErrorKind::InvalidPasetoToken.into());
        }
      } else {
        return Err(ErrorKind::InvalidPasetoToken.into());
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
pub fn validate_local_token(token: String, footer: Option<String>, mut key: Vec<u8>) -> Result<JsonValue> {
  if token.starts_with("v2.local.") {
    let token = try!(V2Decrypt(token, footer, &mut key));
    return validate_potential_json_blob(token);
  } else if token.starts_with("v1.local.") {
    let token = try!(V1Decrypt(token, footer, &key));
    return validate_potential_json_blob(token);
  }

  return Err(ErrorKind::InvalidPasetoToken.into());
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
pub fn validate_local_token(token: String, footer: Option<String>, key: Vec<u8>) -> Result<Jsonvalue> {
  let token = try!(V1Decrypt(token, footer, &key));
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
pub fn validate_local_token(token: String, footer: Option<String>, mut key: Vec<u8>) -> Result<Jsonvalue> {
  let token = try!(V2Decrypt(token, footer, &mut key));
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
pub fn validate_public_token(token: String, footer: Option<String>, key: PasetoPublicKey) -> Result<JsonValue> {
  if token.starts_with("v2.public.") {
    return match key {
      PasetoPublicKey::ED25519KeyPair(key_pair) => {
        let internal_msg = try!(V2Verify(token, footer, &key_pair));
        validate_potential_json_blob(internal_msg)
      }
      _ => Err(ErrorKind::InvalidKey.into()),
    };
  } else if token.starts_with("v1.public.") {
    return match key {
      PasetoPublicKey::RSAPublicKey(key_content) => {
        let internal_msg = try!(V1Verify(token, footer, &key_content));
        validate_potential_json_blob(internal_msg)
      }
      _ => Err(ErrorKind::InvalidKey.into()),
    };
  }

  return Err(ErrorKind::InvalidPasetoToken.into());
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
pub fn validate_public_token(token: String, footer: Option<String>, key: PasetoPublicKey) -> Result<Jsonvalue> {
  return match key {
    PasetoPublicKey::RSAPublicKey(key_content) => {
      let internal_msg = try!(V1Verify(token, footer, &key_content));
      validate_potential_json_blob(internal_msg)
    }
    _ => Err(ErrorKind::InvalidKey.into()),
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
pub fn validate_public_token(token: String, footer: Option<String>, key: PasetoPublicKey) -> Result<Jsonvalue> {
  return match key {
    PasetoPublicKey::ED25519KeyPair(key_pair) => {
      let internal_msg = try!(V2Verify(token, footer, &key_pair));
      validate_potential_json_blob(internal_msg)
    }
    _ => Err(ErrorKind::InvalidKey.into()),
  };
}

#[cfg(test)]
mod unit_tests {
  use super::*;
  use tokens::builder::*;

  use ring::rand::SystemRandom;
  use untrusted::Input as UntrustedInput;

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
      token,
      Some(String::from("footer")),
      Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()),
    ).expect("Failed to validate token!");
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

    assert!(
      validate_local_token(
        token,
        Some(String::from("footer")),
        Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes())
      ).is_err()
    );
  }

  #[test]
  fn valid_pub_token_passes_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_untrusted = UntrustedInput::from(&key_pkcs8);
    let as_key = Ed25519KeyPair::from_pkcs8(as_untrusted.clone()).expect("Failed to parse keypair");
    let cloned_key = Ed25519KeyPair::from_pkcs8(as_untrusted).expect("Failed to parse keypair");

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
      token,
      Some(String::from("footer")),
      PasetoPublicKey::ED25519KeyPair(cloned_key),
    ).expect("Failed to validate token!");
  }

  #[test]
  fn invalid_pub_token_doesnt_validate() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_untrusted = UntrustedInput::from(&key_pkcs8);
    let as_key = Ed25519KeyPair::from_pkcs8(as_untrusted.clone()).expect("Failed to parse keypair");
    let cloned_key = Ed25519KeyPair::from_pkcs8(as_untrusted).expect("Failed to parse keypair");

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

    assert!(
      validate_public_token(
        token,
        Some(String::from("footer")),
        PasetoPublicKey::ED25519KeyPair(cloned_key)
      ).is_err()
    );
  }
}
