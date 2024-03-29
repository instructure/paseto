//! "Easy Tokens", or helper functions to make building/validating tokens easier.
//!
//! The token builder is in general the recommended way to build, and validate
//! paseto tokens. Not only does it do things like validate expirey time on verification
//! It gives you a nice builder pattern to make setting common claims easier.
//!
//! See:
//!
//!   - [`self::builder::PasetoBuilder`]: Building a token of any kind.
//!   - [`self::validate_local_token`]: validating a: `(v1.v2).local.` paseto token.
//!   - [`self::validate_public_token`]: validating a: `(v1.v2).public.` paseto token.
//!   - [`self::validate_potential_json_blob`]: if you manually decrypted a token, and just want to validate the JSON body.

use crate::errors::{GenericError, PasetoError};

#[cfg(feature = "v1")]
use crate::v1::{decrypt_paseto as V1Decrypt, verify_paseto as V1Verify};
#[cfg(feature = "v2")]
use crate::v2::{decrypt_paseto as V2Decrypt, verify_paseto as V2Verify};

#[cfg(feature = "easy_tokens_chrono")]
use chrono::prelude::*;
#[cfg(feature = "v2")]
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{from_str as ParseJson, Value as JsonValue};
#[cfg(feature = "easy_tokens_time")]
use time::OffsetDateTime;

pub mod builder;
pub use self::builder::*;

/// A small wrapper around all the types of public keys that can be used for
/// signing data. For Algorithim Lucidity, and ease of APIs.
pub enum PasetoPublicKey<'a> {
	/// A RSA Public Key in DER format as a byte array.
	#[cfg(feature = "v1")]
	RSAPublicKey(&'a [u8]),
	/// An ED25519 public key, but pass in the key pair for api ease.
	#[cfg(feature = "v2")]
	ED25519KeyPair(&'a Ed25519KeyPair),
	/// An ED25519 Public Key as a byte array.
	#[cfg(feature = "v2")]
	ED25519PublicKey(&'a [u8]),
}

/// Specifies which time crate will be used as backend for validating a token's
/// datetimes, e.g. `issued_at`. The available backends are [`Chrono`] and [`Time`],
/// the can be enabled via the features `easy_tokens_chrono` and `easy_tokens_time`.
/// The default feature and backend is [`Chrono`].
///
/// [`Chrono`]: https://docs.rs/chrono/*/chrono/index.html
/// [`Time`]: https://docs.rs/time/*/time/index.html
pub enum TimeBackend {
	#[cfg(feature = "easy_tokens_chrono")]
	Chrono,
	#[cfg(feature = "easy_tokens_time")]
	Time,
}

/// Validates a potential json data blob, returning a [`JsonValue`].
///
/// This specifically validates:
///   * `iat` (issued at)
///   * `exp` (expired)
///   * `nbf` (not before)
///
/// This specifically does not validate:
///   * `audience`
///   * `jti`
///   * `issuedBy`
///   * `subject`
///
/// # Errors
///
/// - if the data of the token is not valid JSON
/// - the json contains invalid `iat`, `exp`, or `nbf` values.
pub fn validate_potential_json_blob(
	data: &str,
	backend: &TimeBackend,
) -> Result<JsonValue, PasetoError> {
	let value: JsonValue = ParseJson(data)?;

	match backend {
		#[cfg(feature = "easy_tokens_chrono")]
		TimeBackend::Chrono => {
			let iat_value = value.get("iat");
			if iat_value.is_some() {
				let parsed_iat = iat_value
					.and_then(serde_json::Value::as_str)
					.ok_or(GenericError::UnparseableTokenDate { claim_name: "iat" })
					.and_then(|iat| {
						iat.parse::<DateTime<Utc>>()
							.map_err(|_| GenericError::UnparseableTokenDate { claim_name: "iat" })
					})?;

				if parsed_iat > Utc::now() {
					return Err(GenericError::InvalidIssuedAtToken {}.into());
				}
			}

			let exp_value = value.get("exp");
			if exp_value.is_some() {
				let parsed_exp = exp_value
					.and_then(serde_json::Value::as_str)
					.ok_or(GenericError::UnparseableTokenDate { claim_name: "exp" })
					.and_then(|exp| {
						exp.parse::<DateTime<Utc>>()
							.map_err(|_| GenericError::UnparseableTokenDate { claim_name: "exp" })
					})?;

				if parsed_exp < Utc::now() {
					return Err(GenericError::ExpiredToken {}.into());
				}
			}

			let nbf_value = value.get("nbf");
			if nbf_value.is_some() {
				let parsed_nbf = nbf_value
					.and_then(serde_json::Value::as_str)
					.ok_or(GenericError::UnparseableTokenDate { claim_name: "nbf" })
					.and_then(|nbf| {
						nbf.parse::<DateTime<Utc>>()
							.map_err(|_| GenericError::UnparseableTokenDate { claim_name: "nbf" })
					})?;

				if parsed_nbf > Utc::now() {
					return Err(GenericError::InvalidNotBeforeToken {}.into());
				}
			}

			Ok(value)
		}
		#[cfg(feature = "easy_tokens_time")]
		TimeBackend::Time => {
			let iat_value = value.get("iat");
			if iat_value.is_some() {
				let parsed_iat = iat_value
					.and_then(serde_json::Value::as_str)
					.ok_or(GenericError::UnparseableTokenDate { claim_name: "iat" })
					.and_then(|iat| {
						OffsetDateTime::parse(iat, &time::format_description::well_known::Rfc3339)
							.map_err(|_| GenericError::UnparseableTokenDate { claim_name: "iat" })
					})?;

				if parsed_iat > OffsetDateTime::now_utc() {
					return Err(GenericError::InvalidIssuedAtToken {}.into());
				}
			}

			let exp_value = value.get("exp");
			if exp_value.is_some() {
				let parsed_exp = exp_value
					.and_then(serde_json::Value::as_str)
					.ok_or(GenericError::UnparseableTokenDate { claim_name: "exp" })
					.and_then(|exp| {
						OffsetDateTime::parse(exp, &time::format_description::well_known::Rfc3339)
							.map_err(|_| GenericError::UnparseableTokenDate { claim_name: "exp" })
					})?;

				if parsed_exp < OffsetDateTime::now_utc() {
					return Err(GenericError::ExpiredToken {}.into());
				}
			}

			let nbf_value = value.get("nbf");
			if nbf_value.is_some() {
				let parsed_nbf = nbf_value
					.and_then(serde_json::Value::as_str)
					.ok_or(GenericError::UnparseableTokenDate { claim_name: "nbf" })
					.and_then(|nbf| {
						OffsetDateTime::parse(nbf, &time::format_description::well_known::Rfc3339)
							.map_err(|_| GenericError::UnparseableTokenDate { claim_name: "nbf" })
					})?;

				if parsed_nbf > OffsetDateTime::now_utc() {
					return Err(GenericError::InvalidNotBeforeToken {}.into());
				}
			}

			Ok(value)
		}
	}
}

/// Validate a local token for V1, or V2.
///
/// This specifically validates:
///   * `iat` (issued at)
///   * `exp` (expired)
///   * `nbf` (not before)
///
/// This specifically does not validate:
///   * `audience`
///   * `jti`
///   * `issuedBy`
///   * `subject`
///
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
///
/// # Errors
///
/// 1. If we fail to decrypt the local token.
/// 2. If any of the token fields are invalid: `iat`, `exp`, or `nbf`.
pub fn validate_local_token(
	token: &str,
	footer: Option<&str>,
	key: &[u8],
	backend: &TimeBackend,
) -> Result<JsonValue, PasetoError> {
	#[cfg(feature = "v2")]
	{
		if token.starts_with("v2.local.") {
			let message = V2Decrypt(token, footer, key)?;
			return validate_potential_json_blob(&message, backend);
		}
	}

	#[cfg(feature = "v1")]
	{
		if token.starts_with("v1.local.") {
			let message = V1Decrypt(token, footer, key)?;
			return validate_potential_json_blob(&message, backend);
		}
	}

	Err(GenericError::InvalidToken {}.into())
}

/// Validate a public token for V1, or V2.
///
/// This specifically validates:
///   * `iat` (issued at)
///   * `exp` (expired)
///   * `nbf` (not before)
///
/// This specifically does not validate:
///   * `audience`
///   * `jti`
///   * `issuedBy`
///   * `subject`
///
/// Because we validate these fields the resulting type must be a json object. If it's not
/// please use the protocol impls directly.
///
/// # Errors
///
/// 1. If the token cannot be decrypted.
/// 2. If any of the token fields are invalid: `iat`, `exp`, or `nbf`.
pub fn validate_public_token(
	token: &str,
	footer: Option<&str>,
	key: &PasetoPublicKey,
	backend: &TimeBackend,
) -> Result<JsonValue, PasetoError> {
	#[cfg(feature = "v2")]
	{
		if token.starts_with("v2.public.") {
			return match key {
				PasetoPublicKey::ED25519KeyPair(key_pair) => {
					let internal_msg = V2Verify(token, footer, key_pair.public_key().as_ref())?;
					validate_potential_json_blob(&internal_msg, backend)
				}
				PasetoPublicKey::ED25519PublicKey(pub_key_contents) => {
					let internal_msg = V2Verify(token, footer, pub_key_contents)?;
					validate_potential_json_blob(&internal_msg, backend)
				}
				#[cfg(feature = "v1")]
				_ => Err(GenericError::NoKeyProvided {}.into()),
			};
		}
	}

	#[cfg(feature = "v1")]
	{
		if token.starts_with("v1.public.") {
			return match key {
				PasetoPublicKey::RSAPublicKey(key_content) => {
					let internal_msg = V1Verify(token, footer, key_content)?;
					validate_potential_json_blob(&internal_msg, backend)
				}
				#[cfg(feature = "v2")]
				_ => Err(GenericError::NoKeyProvided {}.into()),
			};
		}
	}

	Err(GenericError::InvalidToken {}.into())
}

#[cfg(test)]
mod unit_tests {
	use super::*;
	#[cfg(feature = "easy_tokens_chrono")]
	use chrono::Duration;
	#[cfg(feature = "v2")]
	use ring::rand::SystemRandom;
	use serde_json::json;

	#[test]
	#[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
	fn valid_enc_token_passes_test() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() + 1, 7, 8)
			.and_hms(9, 10, 11);

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
			&TimeBackend::Chrono,
		)
		.expect("Failed to validate token!");
	}

	#[test]
	#[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
	fn valid_enc_token_expired_test() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() - 1, 7, 8)
			.and_hms(9, 10, 11);

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

		let _error: PasetoError = (GenericError::ExpiredToken {}).into();

		assert!(matches!(
			validate_local_token(
				&token,
				Some("footer"),
				&"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
				&TimeBackend::Chrono
			),
			Err(_error)
		));
	}

	#[test]
	#[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
	fn valid_enc_token_not_before_test() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() - 1, 7, 8)
			.and_hms(9, 10, 11);

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

		let _error: PasetoError = (GenericError::InvalidNotBeforeToken {}).into();

		assert!(matches!(
			validate_local_token(
				&token,
				Some("footer"),
				&"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
				&TimeBackend::Chrono
			),
			Err(_error)
		));
	}

	#[test]
	#[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
	fn invalid_enc_token_doesnt_validate() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() - 1, 7, 8)
			.and_hms(9, 10, 11);

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
	#[cfg(all(
		feature = "v2",
		feature = "easy_tokens_chrono",
		not(feature = "easy_tokens_time")
	))]
	fn valid_pub_token_passes_test() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() + 1, 7, 8)
			.and_hms(9, 10, 11);

		let sys_rand = SystemRandom::new();
		let key_pkcs8 =
			Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
		let as_key =
			Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

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
			&TimeBackend::Chrono,
		)
		.expect("Failed to validate token!");
	}

	#[test]
	#[cfg(all(
		feature = "v2",
		feature = "easy_tokens_chrono",
		not(feature = "easy_tokens_time")
	))]
	fn validate_pub_key_only_v2() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() + 1, 7, 8)
			.and_hms(9, 10, 11);

		let sys_rand = SystemRandom::new();
		let key_pkcs8 =
			Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
		let as_key =
			Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

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
			&TimeBackend::Chrono,
		)
		.expect("Failed to validate token!");
	}

	#[test]
	#[cfg(all(
		feature = "v2",
		feature = "easy_tokens_chrono",
		not(feature = "easy_tokens_time")
	))]
	fn invalid_pub_token_doesnt_validate() {
		let current_date_time = Utc::now();
		let dt = Utc
			.ymd(current_date_time.year() - 1, 7, 8)
			.and_hms(9, 10, 11);

		let sys_rand = SystemRandom::new();
		let key_pkcs8 =
			Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
		let as_key =
			Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

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

		assert!(validate_public_token(
			&token,
			Some("footer"),
			&PasetoPublicKey::ED25519KeyPair(&as_key),
			&TimeBackend::Chrono
		)
		.is_err());
	}

	#[test]
	#[cfg(all(
		feature = "v2",
		feature = "easy_tokens_chrono",
		not(feature = "easy_tokens_time")
	))]
	fn allows_validation_without_iat_exp_nbf() {
		let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		let state = PasetoBuilder::new()
			.set_encryption_key(key.as_bytes())
			.build()
			.expect("failed to construct paseto token");

		assert!(
			validate_local_token(&state, None, key.as_bytes(), &TimeBackend::Chrono).is_ok(),
			"Failed to validate token without nbf/iat/exp is okay!"
		);
	}
}
