//! ["Direct" use of public (signed but readable) tokens for V1 of Paseto.](https://github.com/paseto-standard/paseto-spec/blob/8b3fed8240e203b058649d01a82a8c412087bc87/docs/01-Protocol-Versions/Version1.md#sign)

use crate::{
	errors::{GenericError, PasetoError, RsaKeyErrors},
	pae::pae,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, UnparsedPublicKey, RSA_PSS_2048_8192_SHA384, RSA_PSS_SHA384};

const HEADER: &str = "v1.public.";

/// Sign a paseto token using `v1` of Paseto.
///
/// Returns a result of the token as a string if encryption was successful.
///
/// # Errors
///
/// - If the RSA Public Modulus Len is not 256 (you pass an invalid RSA Key).
/// - If we fail to talk to the system random number generator to generate random numbers.
/// - If we fail to call openssl to sign your data.
pub fn public_paseto(
	msg: &str,
	footer: Option<&str>,
	key_pair: &RsaKeyPair,
) -> Result<String, PasetoError> {
	if key_pair.public_modulus_len() != 256 {
		return Err(RsaKeyErrors::InvalidKey {}.into());
	}
	let footer_frd = footer.unwrap_or("");

	let pre_auth = pae(&[HEADER.as_bytes(), msg.as_bytes(), footer_frd.as_bytes()]);
	let random = SystemRandom::new();

	let mut signed_msg = [0; 256];
	let sign_res = key_pair.sign(&RSA_PSS_SHA384, &random, &pre_auth, &mut signed_msg);
	if sign_res.is_err() {
		return Err(RsaKeyErrors::SignError {}.into());
	}

	let mut combined_vec = Vec::new();
	combined_vec.extend_from_slice(msg.as_bytes());
	combined_vec.extend_from_slice(&signed_msg);

	let token = if footer_frd.is_empty() {
		format!(
			"{}{}",
			HEADER,
			encode_config(&combined_vec, URL_SAFE_NO_PAD)
		)
	} else {
		format!(
			"{}{}.{}",
			HEADER,
			encode_config(&combined_vec, URL_SAFE_NO_PAD),
			encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
		)
	};

	Ok(token)
}

/// Verifies the signature of a paseto token using `v1` of Paseto, validating the footer.
///
/// Returns the contents of the token as a string.
///
/// # Errors
///
/// - If the token is not in the proper format: `v1.public.${signed_encoded_data}(.{optional_footer})?`
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
		return Err(GenericError::InvalidToken {}.into());
	}

	let has_provided_footer = footer.is_some();
	let footer_as_str = footer.unwrap_or("");

	if has_provided_footer {
		if token_parts.len() < 4 {
			return Err(GenericError::InvalidFooter {}.into());
		}
		let footer_encoded = encode_config(footer_as_str.as_bytes(), URL_SAFE_NO_PAD);

		if ConstantTimeEquals(footer_encoded.as_bytes(), token_parts[3].as_bytes()).is_err() {
			return Err(GenericError::InvalidFooter {}.into());
		}
	}

	if token_parts[0] != "v1" || token_parts[1] != "public" {
		return Err(GenericError::InvalidToken {}.into());
	}

	let decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)
		.map_err(|e| PasetoError::GenericError(GenericError::Base64Error(e)))?;
	let decoded_len = decoded.len();
	let (message, sig) = decoded.split_at(decoded_len - 256);

	let pre_auth = pae(&[HEADER.as_bytes(), message, footer_as_str.as_bytes()]);

	let pk_unparsed = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, public_key);
	let verify_result = pk_unparsed.verify(&pre_auth, sig);
	if verify_result.is_err() {
		return Err(GenericError::InvalidToken {}.into());
	}

	String::from_utf8(Vec::from(message))
		.map_err(|e| PasetoError::GenericError(GenericError::Utf8Error(e)))
}

#[cfg(test)]
mod unit_tests {
	use super::*;

	use ring::signature::RsaKeyPair;

	#[test]
	fn test_v1_public() {
		let private_key = include_bytes!("signature_rsa_example_private_key.der");
		let public_key = include_bytes!("signature_rsa_example_public_key.der");

		let key_pair = RsaKeyPair::from_der(private_key).expect("Bad Private Key pkcs!");

		// Test keys without footers.
		let public_token_one = public_paseto("msg", None, &key_pair)
			.expect("Failed to encode public paseto v1 msg with no footer!");
		// Remember raw protocol doesn't validate expires. We're just ensuring we can encode it.
		let public_token_two = public_paseto(
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
			None,
			&key_pair,
		)
		.expect("Failed to encode public paseto v1 json blob with no footer!");

		let verified_one = verify_paseto(&public_token_one, None, public_key)
			.expect("Failed to verify public paseto v1 msg with no footer!");
		let verified_two = verify_paseto(&public_token_two, None, public_key)
			.expect("Failed to verify public paseto v1 json blob with no footer!");

		assert_eq!(verified_one, "msg");
		assert_eq!(
			verified_two,
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
		);

		// Attempt to verify with a footer
		let should_not_verify_one = verify_paseto(&public_token_one, Some("hoi"), public_key);
		assert!(should_not_verify_one.is_err());

		let public_token_three = public_paseto("msg", Some("data"), &key_pair)
			.expect("Failed to encode public paseto v1 msg with footer!");
		let public_token_four = public_paseto(
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
			Some("data"),
			&key_pair,
		)
		.expect("Failed to encode public paseto v1 json blob with footer!");

		let verified_three = verify_paseto(&public_token_three, Some("data"), public_key)
			.expect("Failed to verify public paseto v1 msg with footer!");
		let verified_four = verify_paseto(&public_token_four, Some("data"), public_key)
			.expect("Failed to verify public paseto v1 json blob with footer!");

		assert_eq!(verified_three, "msg");
		assert_eq!(
			verified_four,
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
		);

		// Ensure that no footer + incorrect footer fail to validate.
		let should_not_verify_two = verify_paseto(&public_token_three, None, public_key);
		let should_not_verify_three = verify_paseto(&public_token_three, Some("test"), public_key);

		assert!(should_not_verify_two.is_err());
		assert!(should_not_verify_three.is_err());
	}
}
