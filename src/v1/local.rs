//! ["Direct" use of local (symmetrically-encrypted) tokens for V1 of Paseto.](https://github.com/paseto-standard/paseto-spec/blob/8b3fed8240e203b058649d01a82a8c412087bc87/docs/01-Protocol-Versions/Version1.md#encrypt)

use crate::{
	errors::{GenericError, PasetoError, SodiumErrors},
	pae::pae,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use openssl::symm;
use ring::constant_time::verify_slices_are_equal as ConstantTimeEquals;
use ring::hkdf::{Salt, HKDF_SHA384};
use ring::hmac::{sign, Key, HMAC_SHA384};
use ring::rand::{SecureRandom, SystemRandom};

const HEADER: &str = "v1.local.";

/// Encrypt a paseto token using `v1` of Paseto.
///
/// Keys must be exactly 32 bytes long, this is a requirement of the underlying
/// algorithim. Returns a result of the token as a string if encryption was successful.
///
/// # Errors
///
/// - If you pass in a key that is not exactly 32 bytes in length.
/// - If we fail to talk to the system random number generator to generate 32 bytes.
/// - If the calls to openssl to encrypt your data fails.
pub fn local_paseto(msg: &str, footer: Option<&str>, key: &[u8]) -> Result<String, PasetoError> {
	if key.len() != 32 {
		return Err(SodiumErrors::InvalidKeySize {
			size_needed: 32,
			size_provided: key.len(),
		}
		.into());
	}

	let rng = SystemRandom::new();
	let mut buff: [u8; 32] = [0_u8; 32];
	let res = rng.fill(&mut buff);
	if res.is_err() {
		return Err(PasetoError::GenericError(GenericError::RandomError {}));
	}

	underlying_local_paseto(msg, footer, &buff, key)
}

/// Performs the underlying encryption of a paseto token. Split for ease in unit testing.
fn underlying_local_paseto(
	msg: &str,
	footer: Option<&str>,
	random_nonce: &[u8],
	key: &[u8],
) -> Result<String, PasetoError> {
	let footer_frd = footer.unwrap_or("");
	let true_nonce = calculate_hashed_nonce(msg.as_bytes(), random_nonce);

	let (as_salt, ctr_nonce) = true_nonce.split_at(16);
	let hkdf_salt = Salt::new(HKDF_SHA384, as_salt);

	let mut ek = [0; 32];
	let mut ak = [0; 32];

	let encryptionkey_info = ["paseto-encryption-key".as_bytes()];
	let authkey_info = ["paseto-auth-key-for-aead".as_bytes()];

	let extracted = hkdf_salt.extract(key);
	let encryptionkey_wrapped_res = extracted.expand(&encryptionkey_info, CustomKeyWrapper(32));
	let authkey_wrapped_res = extracted.expand(&authkey_info, CustomKeyWrapper(32));
	if encryptionkey_wrapped_res.is_err() || authkey_wrapped_res.is_err() {
		return Err(GenericError::BadHkdf {}.into());
	}
	let encryptionkey_fill_res = encryptionkey_wrapped_res.unwrap().fill(&mut ek);
	let accesskey_fill_res = authkey_wrapped_res.unwrap().fill(&mut ak);
	if encryptionkey_fill_res.is_err() || accesskey_fill_res.is_err() {
		return Err(GenericError::BadHkdf {}.into());
	}

	let cipher = symm::Cipher::aes_256_ctr();
	let crypted = symm::encrypt(cipher, &ek, Some(ctr_nonce), msg.as_bytes())?;

	let pre_auth = pae(&[
		HEADER.as_bytes(),
		&true_nonce,
		&crypted,
		footer_frd.as_bytes(),
	]);

	let mac_key = Key::new(HMAC_SHA384, &ak);
	let signed = sign(&mac_key, &pre_auth);
	let raw_bytes_from_hmac = signed.as_ref();

	let mut concated_together = Vec::new();
	concated_together.extend_from_slice(&true_nonce);
	concated_together.extend_from_slice(&crypted);
	concated_together.extend_from_slice(raw_bytes_from_hmac);

	let token = if footer_frd.is_empty() {
		format!(
			"{}{}",
			HEADER,
			encode_config(&concated_together, URL_SAFE_NO_PAD)
		)
	} else {
		format!(
			"{}{}.{}",
			HEADER,
			encode_config(&concated_together, URL_SAFE_NO_PAD),
			encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
		)
	};

	Ok(token)
}

/// An implementation of `get_nonce` from the docs in paseto version one.
///
/// This function is to ensure that an RNG failure does not result in a
/// nonce-misuse condition that breaks the security of our stream cipher.
#[must_use]
fn calculate_hashed_nonce(msg: &[u8], random_nonce: &[u8]) -> Vec<u8> {
	let mac_key = Key::new(HMAC_SHA384, random_nonce);
	let signed = sign(&mac_key, msg);
	Vec::from(&signed.as_ref()[0..32])
}

/// A small module containing a simple structure that allows us to implement
/// hkdf on any type regardless if we own it or not.
///
/// BORROWED FROM RING Itself.
/// LICENSE: <https://github.com/briansmith/ring/blob/master/LICENSE>
struct CustomKeyWrapper<T>(pub T);

impl ring::hkdf::KeyType for CustomKeyWrapper<usize> {
	fn len(&self) -> usize {
		self.0
	}
}

impl From<ring::hkdf::Okm<'_, CustomKeyWrapper<usize>>> for CustomKeyWrapper<Vec<u8>> {
	fn from(okm: ring::hkdf::Okm<CustomKeyWrapper<usize>>) -> Self {
		let mut r = vec![0_u8; okm.len().0];
		okm.fill(&mut r).unwrap();
		CustomKeyWrapper(r)
	}
}

/// Decrypt a paseto token using `v1` of Paseto, validating the footer.
///
/// Returns the contents of the token as a string.
///
/// # Errors
///
/// - If the token is not in the proper format: `v1.local.${encrypted_data}(.{optional_footer})?`
/// - If the footer on the token did not match the footer passed in.
/// - If we failed to decrypt the data.
/// - If the data contained in the token was not valid utf-8.
pub fn decrypt_paseto(
	token: &str,
	footer: Option<&str>,
	key: &[u8],
) -> Result<String, PasetoError> {
	let token_parts = token.split('.').collect::<Vec<_>>();
	if token_parts.len() < 3 {
		return Err(GenericError::InvalidToken {}.into());
	}

	let is_footer_some = footer.is_some();
	let footer_str = footer.unwrap_or("");

	if is_footer_some {
		if token_parts.len() < 4 {
			return Err(GenericError::InvalidFooter {}.into());
		}
		let as_base64 = encode_config(footer_str.as_bytes(), URL_SAFE_NO_PAD);

		if ConstantTimeEquals(as_base64.as_bytes(), token_parts[3].as_bytes()).is_err() {
			return Err(GenericError::InvalidFooter {}.into());
		}
	}

	if token_parts[0] != "v1" || token_parts[1] != "local" {
		return Err(GenericError::InvalidToken {}.into());
	}
	let decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)
		.map_err(|e| PasetoError::GenericError(GenericError::Base64Error(e)))?;
	let (nonce, t_and_c) = decoded.split_at(32);
	// NLL :shakefists:
	let t_and_c_vec = Vec::from(t_and_c);
	let t_and_c_len = t_and_c_vec.len();
	let (ciphertext, mac) = t_and_c_vec.split_at(t_and_c_len - 48);

	let nonce = Vec::from(nonce);
	let (as_salt, ctr_nonce) = nonce.split_at(16);
	let hkdf_salt = Salt::new(HKDF_SHA384, as_salt);

	let mut ek = [0; 32];
	let mut ak = [0; 32];

	let extracted = hkdf_salt.extract(key);
	let encryptionkey_info = ["paseto-encryption-key".as_bytes()];
	let authkey_info = ["paseto-auth-key-for-aead".as_bytes()];

	let encryptionkey_wrapped_res = extracted
		.expand(&encryptionkey_info, CustomKeyWrapper(32))
		.map_err(|_| GenericError::BadHkdf {})?;
	let authkey_wrapped_res = extracted
		.expand(&authkey_info, CustomKeyWrapper(32))
		.map_err(|_| GenericError::BadHkdf {})?;
	encryptionkey_wrapped_res
		.fill(&mut ek)
		.map_err(|_| GenericError::BadHkdf {})?;
	authkey_wrapped_res
		.fill(&mut ak)
		.map_err(|_| GenericError::BadHkdf {})?;

	let pre_auth = pae(&[HEADER.as_bytes(), &nonce, ciphertext, footer_str.as_bytes()]);

	let mac_key = Key::new(HMAC_SHA384, &ak);
	let signed = sign(&mac_key, &pre_auth);
	let raw_bytes_from_hmac = signed.as_ref();

	if ConstantTimeEquals(raw_bytes_from_hmac, mac).is_err() {
		return Err(GenericError::InvalidToken {}.into());
	}

	let cipher = symm::Cipher::aes_256_ctr();
	let decrypted = symm::decrypt(cipher, &ek, Some(ctr_nonce), ciphertext)?;

	String::from_utf8(decrypted).map_err(|e| PasetoError::GenericError(GenericError::Utf8Error(e)))
}

#[cfg(test)]
mod unit_tests {
	use super::*;
	use hex;
	use ring::rand::{SecureRandom, SystemRandom};

	#[test]
	fn test_v1_local() {
		let rng = SystemRandom::new();
		let mut key_buff: [u8; 32] = [0_u8; 32];
		rng.fill(&mut key_buff).expect("Failed to fill key_buff!");

		// Try to encrypt without footers.
		let message_a =
			local_paseto("msg", None, &key_buff).expect("Failed to encrypt V1 Paseto string");
		// NOTE: This test is just ensuring we can encode a json object, remember these internal impls
		// don't check for expires being valid!
		let message_b = local_paseto(
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
			None,
			&key_buff,
		)
		.expect("Failed to encrypt V1 Paseto Json BLOB");

		assert!(message_a.starts_with("v1.local."));
		assert!(message_b.starts_with("v1.local."));

		let decrypted_a = decrypt_paseto(&message_a, None, &key_buff)
			.expect("Failed to decrypt V1 Paseto String");
		let decrypted_b = decrypt_paseto(&message_b, None, &key_buff)
			.expect("Failed to decrypt V1 Paseto JSON Blob");

		assert_eq!(decrypted_a, "msg");
		assert_eq!(
			decrypted_b,
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
		);

		let should_fail_decryption_a = decrypt_paseto(&message_a, Some("data"), &key_buff);
		assert!(should_fail_decryption_a.is_err());

		// Try with footers.
		let message_c = local_paseto("msg", Some("data"), &key_buff)
			.expect("Failed to encrypt V1 Paseto String with footer!");
		let message_d = local_paseto(
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}",
			Some("data"),
			&key_buff,
		)
		.expect("Failed to encrypt V1 Paseto Json blob with footer!");

		assert!(message_c.starts_with("v1.local."));
		assert!(message_d.starts_with("v1.local."));

		let decrypted_c = decrypt_paseto(&message_c, Some("data"), &key_buff)
			.expect("Failed to decrypt V1 Paseto String with footer!");
		let decrypted_d = decrypt_paseto(&message_d, Some("data"), &key_buff)
			.expect("Failed to decrypt V1 Paseto Json Blob with footer!");

		assert_eq!(decrypted_c, "msg");
		assert_eq!(
			decrypted_d,
			"{\"data\": \"yo bro\", \"expires\": \"2018-01-01T00:00:00+00:00\"}"
		);

		// Try with no footer + invalid footer.
		let should_fail_decryption_b = decrypt_paseto(&message_c, None, &key_buff);
		let should_fail_decryption_c = decrypt_paseto(&message_c, Some("invalid"), &key_buff);

		assert!(should_fail_decryption_b.is_err());
		assert!(should_fail_decryption_c.is_err());
	}

	#[test]
	fn test_nonce_derivation() {
		// Constants copied directly from paseto source.
		let msg_a = "The quick brown fox jumped over the lazy dog.";
		let msg_b = "The quick brown fox jumped over the lazy dof.";
		let nonce =
			hex::decode("808182838485868788898a8b8c8d8e8f").expect("Failed to decode nonce!");

		let calculated_nonce_a = calculate_hashed_nonce(msg_a.as_bytes(), &nonce);
		let calculated_nonce_b = calculate_hashed_nonce(msg_b.as_bytes(), &nonce);

		assert_eq!(
			"5e13b4f0fc111bf0cf9de4e97310b687858b51547e125790513cc1eaaef173cc",
			hex::encode(&calculated_nonce_a)
		);
		assert_eq!(
			"e1ba992f5cccd31714fd8c73adcdadabb00d0f23955a66907170c10072d66ffd",
			hex::encode(&calculated_nonce_b)
		)
	}
}
