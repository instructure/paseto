//! Provides a "nice" wrapper around paseto tokens in order to check things such as "Expiration".
//! Issuer, etc.

use crate::errors::GenericError;

#[cfg(feature = "v1")]
use crate::v1::{decrypt_paseto as V1Decrypt, verify_paseto as V1Verify};
#[cfg(feature = "v2")]
use crate::v2::{decrypt_paseto as V2Decrypt, verify_paseto as V2Verify};

#[cfg(feature = "easy_tokens_chrono")]
use chrono::prelude::*;
#[cfg(feature = "easy_tokens_time")]
use time::OffsetDateTime;
use failure::Error;
#[cfg(feature = "v2")]
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{from_str as ParseJson, Value as JsonValue};

pub mod builder;
pub use self::builder::*;

/// Wraps the two paseto public key types so we can just have a `validate_public_token`
/// method without splitting the two implementations.
pub enum PasetoPublicKey<'a> {
  #[cfg(feature = "v1")]
  RSAPublicKey(&'a [u8]),
  #[cfg(feature = "v2")]
  ED25519KeyPair(&'a Ed25519KeyPair),
  #[cfg(feature = "v2")]
  ED25519PublicKey(&'a [u8]),
}

/// Specifies which time crate will be used as backend for validating a token's
/// datetimes, i.e. issued_at. The available backends are [`Chrono`] and [`Time`],
/// the can be enabled via the features `easy_tokens_chrono` and `easy_tokens_time`.
/// The default feature and backend is [`Chrono`].
///
/// [`Chrono`]: https://docs.rs/chrono/*/chrono/index.html
/// [`Time`]: https://docs.rs/time/*/time/index.html
pub enum TimeBackend {
  #[cfg(feature = "easy_tokens_chrono")]
  Chrono,
  #[cfg(feature = "easy_tokens_time")]
  Time
}

/// Validates a potential json data blob, returning a JsonValue.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
///
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
pub fn validate_potential_json_blob(data: &str, backend: &TimeBackend) -> Result<JsonValue, Error> {
  let value: JsonValue = ParseJson(data)?;

  match backend {
    #[cfg(feature = "easy_tokens_chrono")]
    TimeBackend::Chrono => {
      let parsed_iat = value.get("iat").and_then(|issued_at| issued_at.as_str())
        .ok_or(GenericError::UnparseableTokenDate {})
        .and_then(|iat| iat.parse::<DateTime<Utc>>()
          .map_err(|_| GenericError::UnparseableTokenDate {})
        )?;

      if parsed_iat > Utc::now() {
        return Err(GenericError::InvalidIssuedAtToken {})?;
      }

      let parsed_exp = value.get("exp").and_then(|expired| expired.as_str())
        .ok_or(GenericError::UnparseableTokenDate {})
        .and_then(|exp| exp.parse::<DateTime<Utc>>()
          .map_err(|_| GenericError::UnparseableTokenDate {})
        )?;

      if parsed_exp < Utc::now() {
        return Err(GenericError::ExpiredToken {})?;
      }

      let parsed_nbf = value.get("nbf").and_then(|not_before| not_before.as_str())
        .ok_or(GenericError::UnparseableTokenDate {})
        .and_then(|nbf| nbf.parse::<DateTime<Utc>>()
          .map_err(|_| GenericError::UnparseableTokenDate {})
        )?;

      if parsed_nbf > Utc::now() {
        return Err(GenericError::InvalidNotBeforeToken {})?;
      }

      Ok(value)
    }
    #[cfg(feature = "easy_tokens_time")]
    TimeBackend::Time => {
      let parsed_iat = value.get("iat").and_then(|issued_at| issued_at.as_str())
        .ok_or(GenericError::UnparseableTokenDate {})
        .and_then(|iat| OffsetDateTime::parse(iat, time::Format::Rfc3339)
          .map_err(|_| GenericError::UnparseableTokenDate {})
        )?;

      if parsed_iat > OffsetDateTime::now_utc() {
        return Err(GenericError::InvalidIssuedAtToken {})?;
      }

      let parsed_exp = value.get("exp").and_then(|expired| expired.as_str())
        .ok_or(GenericError::UnparseableTokenDate {})
        .and_then(|exp| OffsetDateTime::parse(exp, time::Format::Rfc3339)
          .map_err(|_| GenericError::UnparseableTokenDate {})
        )?;

      if parsed_exp < OffsetDateTime::now_utc() {
        return Err(GenericError::ExpiredToken {})?;
      }

      let parsed_nbf = value.get("nbf").and_then(|not_before| not_before.as_str())
        .ok_or(GenericError::UnparseableTokenDate {})
        .and_then(|nbf| OffsetDateTime::parse(nbf, time::Format::Rfc3339)
          .map_err(|_| GenericError::UnparseableTokenDate {})
        )?;

      if parsed_nbf > OffsetDateTime::now_utc() {
        return Err(GenericError::InvalidNotBeforeToken {})?;
      }

      Ok(value)
    }
  }
}

/// Validate a local token for V1, or V2.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
///
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
///
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
pub fn validate_local_token(token: &str, footer: Option<&str>, key: &[u8], backend: &TimeBackend) -> Result<JsonValue, Error> {
  #[cfg(feature = "v2")]
  {
    if token.starts_with("v2.local.") {
      let message = V2Decrypt(token, footer, &key)?;
      return validate_potential_json_blob(&message, backend);
    }
  }

  #[cfg(feature = "v1")]
  {
    if token.starts_with("v1.local.") {
      let message = V1Decrypt(token, footer, &key)?;
      return validate_potential_json_blob(&message, backend);
    }
  }

  return Err(GenericError::InvalidToken {})?;
}

/// Validate a public token for V1, or V2.
///
/// This specifically validates:
///   * issued_at
///   * expired
///   * not_before
///
/// This specifically does not validate:
///   * audience
///   * jti
///   * issuedBy
///   * subject
///
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
pub fn validate_public_token(token: &str, footer: Option<&str>, key: &PasetoPublicKey, backend: &TimeBackend) -> Result<JsonValue, Error> {
  #[cfg(feature = "v2")]
  {
    if token.starts_with("v2.public.") {
      return match key {
        PasetoPublicKey::ED25519KeyPair(key_pair) => {
          let internal_msg = V2Verify(token, footer, key_pair.public_key().as_ref())?;
          validate_potential_json_blob(&internal_msg, backend)
        }
        PasetoPublicKey::ED25519PublicKey(pub_key_contents) => {
          let internal_msg = V2Verify(token, footer, &pub_key_contents)?;
          validate_potential_json_blob(&internal_msg, backend)
        }
        #[cfg(feature = "v1")]
        _ => Err(GenericError::NoKeyProvided {})?,
      };
    }
  }

  #[cfg(feature = "v1")]
  {
    if token.starts_with("v1.public.") {
      return match key {
        PasetoPublicKey::RSAPublicKey(key_content) => {
          let internal_msg = V1Verify(token, footer, &key_content)?;
          validate_potential_json_blob(&internal_msg, backend)
        }
        #[cfg(feature = "v2")]
        _ => Err(GenericError::NoKeyProvided {})?,
      };
    }
  }

  return Err(GenericError::InvalidToken {})?;
}

#[cfg(test)]
mod unit_tests {
  use super::*;
  #[cfg(feature = "v2")]
  use ring::rand::SystemRandom;
  use serde_json::json;
  use chrono::Duration;

  #[test]
  #[cfg(feature = "easy_tokens_chrono")]
  fn valid_enc_token_passes_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let token = PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    validate_local_token(
      &token,
      Some("footer"),
      &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
      &TimeBackend::Chrono
    )
    .expect("Failed to validate token!");
  }

  #[test]
  #[cfg(feature = "easy_tokens_chrono")]
  fn valid_enc_token_expired_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let token = PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    let _error: failure::Error = (GenericError::ExpiredToken {}).into();

    assert!(matches!(validate_local_token(
      &token,
      Some("footer"),
      &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
      &TimeBackend::Chrono
    ), Err(_error)));
  }

  #[test]
  #[cfg(feature = "easy_tokens_chrono")]
  fn valid_enc_token_not_before_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let token = PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&(Utc::now() + Duration::days(1)))
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    let _error: failure::Error = (GenericError::InvalidNotBeforeToken {}).into();

    assert!(matches!(validate_local_token(
      &token,
      Some("footer"),
      &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
      &TimeBackend::Chrono
    ), Err(_error)));
  }

  #[test]
  #[cfg(feature = "easy_tokens_chrono")]
  fn invalid_enc_token_doesnt_validate() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let token = PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    assert!(validate_local_token(
      &token,
      Some("footer"),
      &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
      &TimeBackend::Chrono
    )
    .is_err());
  }

  #[test]
  #[cfg(all(feature = "v2", feature = "easy_tokens_chrono"))]
  fn valid_pub_token_passes_test() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = PasetoBuilder::new()
      .set_ed25519_key(&as_key)
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    validate_public_token(
      &token,
      Some("footer"),
      &PasetoPublicKey::ED25519KeyPair(&as_key),
      &TimeBackend::Chrono
    )
    .expect("Failed to validate token!");
  }

  #[test]
  #[cfg(all(feature = "v2", feature = "easy_tokens_chrono"))]
  fn validate_pub_key_only_v2() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = PasetoBuilder::new()
      .set_ed25519_key(&as_key)
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    validate_public_token(
      &token,
      Some("footer"),
      &PasetoPublicKey::ED25519PublicKey(as_key.public_key().as_ref()),
      &TimeBackend::Chrono
    )
    .expect("Failed to validate token!");
  }

  #[test]
  #[cfg(all(feature = "v2", feature = "easy_tokens_chrono"))]
  fn invalid_pub_token_doesnt_validate() {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() - 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = PasetoBuilder::new()
      .set_ed25519_key(&as_key)
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    assert!(validate_public_token(&token, Some("footer"), &PasetoPublicKey::ED25519KeyPair(&as_key), &TimeBackend::Chrono).is_err());
  }
}
