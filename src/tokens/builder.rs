use crate::errors::GenericError;
#[cfg(feature = "v1")]
use crate::errors::RsaKeyErrors;

#[cfg(all(not(feature = "v2"), feature = "v1"))]
use crate::v1::local_paseto as V1Local;
#[cfg(feature = "v1")]
use crate::v1::public_paseto as V1Public;
#[cfg(feature = "v2")]
use crate::v2::{local_paseto as V2Local, public_paseto as V2Public};

#[cfg(feature = "easy_tokens_chrono")]
use chrono::prelude::*;
use failure::Error;
#[cfg(feature = "v2")]
use ring::signature::Ed25519KeyPair;
#[cfg(feature = "v1")]
use ring::signature::RsaKeyPair;
use serde_json::{json, to_string, Value};
#[cfg(feature = "easy_tokens_time")]
use time::OffsetDateTime;

use std::collections::HashMap;

/// A paseto builder.
pub struct PasetoBuilder<'a> {
  /// Set the footer to use for this token.
  footer: Option<&'a str>,
  /// The encryption key to use. If present WILL use LOCAL tokens (or shared key encryption).
  encryption_key: Option<&'a [u8]>,
  /// The RSA Key pairs in DER format, for V1 Public Tokens.
  #[cfg(feature = "v1")]
  rsa_key: Option<&'a [u8]>,
  /// The ED25519 Key Pair, for V2 Public Tokens.
  #[cfg(feature = "v2")]
  ed_key: Option<&'a Ed25519KeyPair>,
  /// Any extra claims you want to store in your json.
  extra_claims: HashMap<&'a str, Value>,
}

impl<'a> PasetoBuilder<'a> {
  /// Creates a new Paseto builder.
  pub fn new() -> PasetoBuilder<'a> {
    PasetoBuilder {
      footer: None,
      encryption_key: None,
      #[cfg(feature = "v1")]
      rsa_key: None,
      #[cfg(feature = "v2")]
      ed_key: None,
      extra_claims: HashMap::new(),
    }
  }

  /// Builds a token.
  pub fn build(&self) -> Result<String, Error> {
    let strd_msg = to_string(&self.extra_claims)?;

    #[cfg(feature = "v2")]
    {
      if let Some(mut enc_key) = self.encryption_key {
        return V2Local(&strd_msg, self.footer.as_deref(), &mut enc_key);
      }
    }

    #[cfg(all(not(feature = "v2"), feature = "v1"))]
    {
      if let Some(mut enc_key) = self.encryption_key {
        return V1Local(&strd_msg, self.footer.as_deref(), &mut enc_key);
      }
    }

    #[cfg(feature = "v2")]
    {
      if let Some(ed_key_pair) = self.ed_key {
        return V2Public(&strd_msg, self.footer.as_deref(), &ed_key_pair);
      }
    }

    #[cfg(feature = "v1")]
    {
      if let Some(the_rsa_key) = self.rsa_key {
        let key_pair = RsaKeyPair::from_der(&the_rsa_key);
        if key_pair.is_err() {
          return Err(RsaKeyErrors::InvalidKey {})?;
        }
        let mut key_pair = key_pair.unwrap();
        return V1Public(&strd_msg, self.footer.as_deref(), &mut key_pair);
      }
    }

    return Err(GenericError::NoKeyProvided {})?;
  }
}

#[cfg(feature = "v1")]
impl<'a> PasetoBuilder<'a> {
  /// Sets the RSA Key on a Paseto builder.
  ///
  /// NOTE: This will not be used if you set a symmetric encryption key, or if you specify an Ed25519 key pair.
  pub fn set_rsa_key(&'a mut self, private_key_der: &'a [u8]) -> &'a mut Self {
    self.rsa_key = Some(private_key_der);
    self
  }
}

#[cfg(feature = "v2")]
impl<'a> PasetoBuilder<'a> {
  /// Sets the ED25519 Key pair.
  ///
  /// NOTE: This will not be used if you set a symmetric encryption key.
  pub fn set_ed25519_key(&'a mut self, key_pair: &'a Ed25519KeyPair) -> &'a mut Self {
    self.ed_key = Some(key_pair);
    self
  }
}

impl<'a> PasetoBuilder<'a> {
  /// Sets the encryption key to use for the paseto token.
  ///
  /// NOTE: If you set this we _*will*_ use a local token.
  pub fn set_encryption_key(&'a mut self, encryption_key: &'a [u8]) -> &'a mut Self {
    self.encryption_key = Some(encryption_key);
    self
  }

  //// Sets the footer to use for this token.
  pub fn set_footer(&'a mut self, footer: &'a str) -> &'a mut Self {
    self.footer = Some(footer);
    self
  }

  /// Sets an arbitrary claim (a key inside the json token).
  pub fn set_claim(&'a mut self, key: &'a str, value: Value) -> &'a mut Self {
    self.extra_claims.insert(key, value);
    self
  }

  /// Sets the audience for this token.
  pub fn set_audience(&'a mut self, audience: &str) -> &'a mut Self {
    self.set_claim("aud", json!(audience))
  }

  /// Sets the expiration date for this token.
  #[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
  pub fn set_expiration(&'a mut self, expiration: &DateTime<Utc>) -> &'a mut Self {
    self.set_claim("exp", json!(expiration))
  }

  /// Sets the expiration date for this token.
  #[cfg(all(feature = "easy_tokens_time", not(feature = "easy_tokens_chrono")))]
  pub fn set_expiration(&'a mut self, expiration: &OffsetDateTime) -> &'a mut Self {
    self.set_claim("exp", json!(expiration))
  }

  /// Sets the expiration date for this token.
  #[cfg(all(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
  pub fn set_expiration_chrono(&'a mut self, expiration: &DateTime<Utc>) -> &'a mut Self {
    self.set_claim("exp", json!(expiration))
  }

  /// Sets the expiration date for this token.
  #[cfg(all(feature = "easy_tokens_time", feature = "easy_tokens_time"))]
  pub fn set_expiration_time(&'a mut self, expiration: &OffsetDateTime) -> &'a mut Self {
    self.set_claim("exp", json!(expiration))
  }

  /// Sets the time this token was issued at.
  ///
  /// issued_at defaults to: Utc::now();
  #[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
  pub fn set_issued_at(&'a mut self, issued_at: Option<DateTime<Utc>>) -> &'a mut Self {
    self.set_claim("iat", json!(issued_at.unwrap_or(Utc::now())))
  }

  /// Sets the time this token was issued at.
  ///
  /// issued_at defaults to: OffsetDateTime::now_utc();
  #[cfg(all(feature = "easy_tokens_time", not(feature = "easy_tokens_chrono")))]
  pub fn set_issued_at(&'a mut self, issued_at: Option<OffsetDateTime>) -> &'a mut Self {
    self.set_claim("iat", json!(issued_at.unwrap_or(OffsetDateTime::now_utc())))
  }

  /// Sets the time this token was issued at.
  ///
  /// issued_at defaults to: Utc::now();
  #[cfg(all(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
  pub fn set_issued_at_chrono(&'a mut self, issued_at: Option<DateTime<Utc>>) -> &'a mut Self {
    self.set_claim("iat", json!(issued_at.unwrap_or(Utc::now())))
  }

  /// Sets the time this token was issued at.
  ///
  /// issued_at defaults to: OffsetDateTime::now_utc();
  #[cfg(all(feature = "easy_tokens_time", feature = "easy_tokens_time"))]
  pub fn set_issued_at_time(&'a mut self, issued_at: Option<OffsetDateTime>) -> &'a mut Self {
    self.set_claim("iat", json!(issued_at.unwrap_or(OffsetDateTime::now_utc())))
  }

  /// Sets the issuer for this token.
  pub fn set_issuer(&'a mut self, issuer: &str) -> &'a mut Self {
    self.set_claim("iss", json!(issuer))
  }

  /// Sets the JTI ID for this token.
  pub fn set_jti(&'a mut self, id: &str) -> &'a mut Self {
    self.set_claim("jti", json!(id))
  }

  /// Sets the not before time.
  #[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
  pub fn set_not_before(&'a mut self, not_before: &DateTime<Utc>) -> &'a mut Self {
    self.set_claim("nbf", json!(not_before))
  }

  /// Sets the not before time.
  #[cfg(all(feature = "easy_tokens_time", not(feature = "easy_tokens_chrono")))]
  pub fn set_not_before(&'a mut self, not_before: &OffsetDateTime) -> &'a mut Self {
    self.set_claim("nbf", json!(not_before))
  }

  /// Sets the not before time.
  #[cfg(all(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
  pub fn set_not_before_chrono(&'a mut self, not_before: &DateTime<Utc>) -> &'a mut Self {
    self.set_claim("nbf", json!(not_before))
  }

  /// Sets the not before time.
  #[cfg(all(feature = "easy_tokens_time", feature = "easy_tokens_time"))]
  pub fn set_not_before_time(&'a mut self, not_before: &OffsetDateTime) -> &'a mut Self {
    self.set_claim("nbf", json!(not_before))
  }

  /// Sets the subject for this token.
  pub fn set_subject(&'a mut self, subject: &str) -> &'a mut Self {
    self.set_claim("sub", json!(subject))
  }
}

#[cfg(test)]
mod unit_test {
  #[cfg(feature = "v2")]
  use {super::*, crate::v2::local::decrypt_paseto as V2Decrypt, serde_json::from_str as ParseJson};

  #[test]
  #[cfg(all(feature = "v2", feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
  fn can_construct_a_token_chrono() {
    let token = PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(&Utc::now())
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&Utc::now())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    let decrypted_token = V2Decrypt(
      &token,
      Some("footer"),
      &mut Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()),
    )
    .expect("Failed to decrypt token constructed with builder!");

    let parsed: Value = ParseJson(&decrypted_token).expect("Failed to parse finalized token as json!");

    assert!(parsed.get("iat").is_some());
    assert!(parsed.get("iss").is_some());
    assert!(parsed.get("aud").is_some());
    assert!(parsed.get("jti").is_some());
    assert!(parsed.get("sub").is_some());
    assert!(parsed.get("claim").is_some());
    assert!(parsed.get("nbf").is_some());
  }

  #[test]
  #[cfg(all(feature = "v2", feature = "easy_tokens_time", not(feature = "easy_tokens_chrono")))]
  fn can_construct_a_token_time() {
    let token = PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(&OffsetDateTime::now_utc())
      .set_issuer("issuer")
      .set_audience("audience")
      .set_jti("jti")
      .set_not_before(&OffsetDateTime::now_utc())
      .set_subject("test")
      .set_claim("claim", json!("data"))
      .set_footer("footer")
      .build()
      .expect("Failed to construct paseto token w/ builder!");

    let decrypted_token = V2Decrypt(
      &token,
      Some("footer"),
      &mut Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()),
    )
    .expect("Failed to decrypt token constructed with builder!");

    let parsed: Value = ParseJson(&decrypted_token).expect("Failed to parse finalized token as json!");

    assert!(parsed.get("iat").is_some());
    assert!(parsed.get("iss").is_some());
    assert!(parsed.get("aud").is_some());
    assert!(parsed.get("jti").is_some());
    assert!(parsed.get("sub").is_some());
    assert!(parsed.get("claim").is_some());
    assert!(parsed.get("nbf").is_some());
  }
}
