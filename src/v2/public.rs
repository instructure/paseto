//! ["Direct" use of public (signed but readable) tokens for V2 of Paseto.](https://github.com/paseto-standard/paseto-spec/blob/8b3fed8240e203b058649d01a82a8c412087bc87/docs/01-Protocol-Versions/Version2.md#sign)

use crate::{
	errors::{GenericError, PasetoError},
	pae::pae,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};

const HEADER: &str = "v2.public.";

/// Sign a paseto token using `v2` of Paseto.
///
/// Returns a result of the token as a string if encryption was successful.
///
/// # Errors
///
/// - If the calls to libsodium to sign your data fails.
pub fn public_paseto(
	msg: &str,
	footer: Option<&str>,
	key_pair: &Ed25519KeyPair,
) -> Result<String, PasetoError> {
	let footer_frd = footer.unwrap_or("");

	let pre_auth = pae(&[HEADER.as_bytes(), msg.as_bytes(), footer_frd.as_bytes()]);

	let sig = key_pair.sign(&pre_auth);
	let mut m_and_sig = Vec::from(msg.as_bytes());
	m_and_sig.extend_from_slice(sig.as_ref());

	let token = if footer_frd.is_empty() {
		format!("{}{}", HEADER, encode_config(&m_and_sig, URL_SAFE_NO_PAD))
	} else {
		format!(
			"{}{}.{}",
			HEADER,
			encode_config(&m_and_sig, URL_SAFE_NO_PAD),
			encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
		)
	};

	Ok(token)
}

/// Verifies the signature of a paseto token using `v2` of Paseto, validating the footer.
///
/// Returns the contents of the token as a string.
///
/// # Errors
///
/// - If the token is not in the proper format: `v2.public.${signed_encoded_data}(.{optional_footer})?`
/// - If the footer on the token did not match the footer passed in.
/// - If we failed to validate the signature of the data.
/// - If the data contained in the token was not valid utf-8.
pub fn verify_paseto(
	token: &str,
	footer: Option<&str>,
	public_key: &[u8],
) -> Result<String, PasetoError> {
	let token_parts = token.split('.').collect::<Vec<_>>();
	if token_parts.len() < 3 {
		return Err(PasetoError::GenericError(GenericError::InvalidToken {}));
	}

	let has_provided_footer = footer.is_some();
	let footer_as_str = footer.unwrap_or("");

	if has_provided_footer {
		if token_parts.len() < 4 {
			return Err(PasetoError::GenericError(GenericError::InvalidFooter {}));
		}
		let footer_encoded = encode_config(footer_as_str.as_bytes(), URL_SAFE_NO_PAD);

		if ConstantTimeEquals(footer_encoded.as_bytes(), token_parts[3].as_bytes()).is_err() {
			return Err(PasetoError::GenericError(GenericError::InvalidFooter {}));
		}
	}

	if token_parts[0] != "v2" || token_parts[1] != "public" {
		return Err(PasetoError::GenericError(GenericError::InvalidToken {}));
	}

	let decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)
		.map_err(|e| PasetoError::GenericError(GenericError::Base64Error(e)))?;
	let decoded_len = decoded.len();
	let (msg, sig) = decoded.split_at(decoded_len - 64);

	let pre_auth = pae(&[HEADER.as_bytes(), msg, footer_as_str.as_bytes()]);

	let pk_unparsed = UnparsedPublicKey::new(&ED25519, public_key);
	let verify_res = pk_unparsed.verify(&pre_auth, sig);
	if verify_res.is_err() {
		return Err(PasetoError::GenericError(GenericError::InvalidToken {}));
	}

	String::from_utf8(Vec::from(msg))
		.map_err(|e| PasetoError::GenericError(GenericError::Utf8Error(e)))
}

#[cfg(test)]
mod unit_tests {
	use super::*;

	use ring::rand::SystemRandom;
	use ring::signature::KeyPair;

	#[test]
	fn paseto_public_verify() {
		let sys_rand = SystemRandom::new();
		let key_pkcs8 =
			Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
		let as_key =
			Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

		// Test messages without footers.
		let public_token_one = public_paseto("msg", None, &as_key)
			.expect("Failed to public encode msg with no footer!");
		// NOTE: This test is just ensuring we can encode a json object, remember these internal impls
		// don't check for expires being valid!
		let public_token_two = public_paseto(
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
			None,
			&as_key,
		)
		.expect("Failed to public encode json blob with no footer!");

		assert!(public_token_one.starts_with("v2.public."));
		assert!(public_token_two.starts_with("v2.public."));

		let verified_one = verify_paseto(
			&public_token_one.clone(),
			None,
			as_key.public_key().as_ref(),
		);
		let verified_two = verify_paseto(&public_token_two, None, as_key.public_key().as_ref());

		// Verify the above tokens.
		assert!(verified_one.is_ok());
		assert!(verified_two.is_ok());
		assert_eq!(verified_one.unwrap(), "msg");
		assert_eq!(
			verified_two.unwrap(),
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
		);

		let should_not_verify_one = verify_paseto(
			&public_token_one,
			Some("data"),
			as_key.public_key().as_ref(),
		);

		// Verify if it doesn't have a footer in public that it won't pass a verification with a footer.
		assert!(should_not_verify_one.is_err());

		// Now lets verify with footers.
		let public_token_three = public_paseto("msg", Some("footer"), &as_key)
			.expect("Failed to public encode msg with footer!");
		let public_token_four = public_paseto(
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
			Some("footer"),
			&as_key,
		)
		.expect("Failed to public encode json blob with footer!");

		assert!(public_token_three.starts_with("v2.public."));
		assert!(public_token_four.starts_with("v2.public."));

		let verified_three = verify_paseto(
			&public_token_three,
			Some("footer"),
			as_key.public_key().as_ref(),
		);
		let verified_four = verify_paseto(
			&public_token_four,
			Some("footer"),
			as_key.public_key().as_ref(),
		);

		// Verify the footer tokens.
		assert!(verified_three.is_ok());
		assert!(verified_four.is_ok());
		assert_eq!(verified_three.unwrap(), "msg");
		assert_eq!(
			verified_four.unwrap(),
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
		);

		// Validate no footer + invalid footer both fail on tokens encode with footer.
		let should_not_verify_two =
			verify_paseto(&public_token_three, None, as_key.public_key().as_ref());
		let should_not_verify_three = verify_paseto(
			&public_token_three,
			Some("bleh"),
			as_key.public_key().as_ref(),
		);

		assert!(should_not_verify_two.is_err());
		assert!(should_not_verify_three.is_err());
	}
}
