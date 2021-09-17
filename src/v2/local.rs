//! An Implementation of Paseto V2 "local" tokens (or tokens that are encrypted with a shared secret).

use crate::{
	errors::{GenericError, PasetoError, SodiumErrors},
	pae::pae,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use blake2::{
	digest::{Update, VariableOutput},
	VarBlake2b,
};
use chacha20poly1305::{
	aead::{Aead, NewAead, Payload},
	XChaCha20Poly1305, XNonce,
};
use ring::{
	constant_time::verify_slices_are_equal as ConstantTimeEquals,
	rand::{SecureRandom, SystemRandom},
};

const HEADER: &str = "v2.local.";

/// Encrypt a "v2.local" paseto token.
///
/// Keys must be exactly 32 bytes long, this is a requirement of the underlying
/// algorithim.
///
/// Returns a result of a string if encryption was successful.
///
/// # Errors
///
/// If random generation of a nonce failed, or encrypting the data failed.
pub fn local_paseto(msg: &str, footer: Option<&str>, key: &[u8]) -> Result<String, PasetoError> {
	let rng = SystemRandom::new();
	let mut buff: [u8; 24] = [0_u8; 24];
	let res = rng.fill(&mut buff);
	if res.is_err() {
		return Err(GenericError::RandomError {}.into());
	}

	if key.len() != 32 {
		return Err(SodiumErrors::InvalidKeySize {
			size_needed: 32,
			size_provided: key.len(),
		}
		.into());
	}

	underlying_local_paseto(msg, footer, &buff, key)
}

/// Performs the underlying encryption of a paseto token. Split for unit testing.
///
/// `msg` - The Msg to Encrypt.
/// `footer` - The footer to add.
/// `nonce_key` - The key to the nonce, should be securely generated.
/// `key` - The key to encrypt the message with.
fn underlying_local_paseto(
	msg: &str,
	footer: Option<&str>,
	nonce_key: &[u8; 24],
	key: &[u8],
) -> Result<String, PasetoError> {
	let footer_frd = footer.unwrap_or("");
	let mut state = VarBlake2b::new_keyed(nonce_key, 24);
	state.update(msg.as_bytes());
	let finalized = state.finalize_boxed();
	let nonce = XNonce::from_slice(finalized.as_ref());
	if let Ok(aead) = XChaCha20Poly1305::new_from_slice(key) {
		let pre_auth = pae(&[HEADER.as_bytes(), finalized.as_ref(), footer_frd.as_bytes()]);
		if let Ok(crypted) = aead.encrypt(
			nonce,
			Payload {
				msg: msg.as_bytes(),
				aad: pre_auth.as_ref(),
			},
		) {
			let mut n_and_c = Vec::new();
			n_and_c.extend_from_slice(finalized.as_ref());
			n_and_c.extend_from_slice(crypted.as_ref());

			let token = if footer_frd.is_empty() {
				format!("{}{}", HEADER, encode_config(&n_and_c, URL_SAFE_NO_PAD))
			} else {
				format!(
					"{}{}.{}",
					HEADER,
					encode_config(&n_and_c, URL_SAFE_NO_PAD),
					encode_config(footer_frd.as_bytes(), URL_SAFE_NO_PAD)
				)
			};

			Ok(token)
		} else {
			Err(SodiumErrors::FunctionError {}.into())
		}
	} else {
		Err(SodiumErrors::InvalidKeySize {
			size_provided: key.len(),
			size_needed: 32,
		}
		.into())
	}
}

/// Decrypt a Paseto TOKEN, validating against an optional footer.
///
/// `token`: The Token to decrypt.
/// `footer`: The Optional footer to validate.
/// `key`: The key to decrypt your Paseto.
///
/// # Errors
///
/// If the token is invalid in anyway, and cannot be decrypted.
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

	if token_parts[0] != "v2" || token_parts[1] != "local" {
		return Err(GenericError::InvalidToken {}.into());
	}

	let mut decoded = decode_config(token_parts[2].as_bytes(), URL_SAFE_NO_PAD)
		.map_err(|e| PasetoError::GenericError(GenericError::Base64Error(e)))?;
	let (nonce, ciphertext) = decoded.split_at_mut(24);

	let pre_auth = pae(&[HEADER.as_bytes(), nonce, footer_str.as_bytes()]);

	let nonce_obj = XNonce::from_slice(nonce);
	let aead = XChaCha20Poly1305::new_from_slice(key)
		.map_err(|_| PasetoError::LibsodiumError(SodiumErrors::InvalidKey {}))?;

	match aead.decrypt(
		nonce_obj,
		Payload {
			msg: ciphertext,
			aad: &pre_auth,
		},
	) {
		Ok(decrypted) => String::from_utf8(decrypted)
			.map_err(|e| PasetoError::GenericError(GenericError::Utf8Error(e))),
		Err(_) => Err(SodiumErrors::FunctionError {}.into()),
	}
}

#[cfg(test)]
mod unit_tests {
	use super::*;

	#[test]
	fn paseto_empty_encrypt_verify() {
		let empty_key = [0; 32];
		let full_key = [255; 32];
		let result = underlying_local_paseto("", None, &[0; 24], &empty_key);
		if result.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", result);
			panic!("Paseto Failure Encryption!");
		}
		let the_str = result.unwrap();

		assert_eq!(
			"v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
			the_str
		);

		let result_full = underlying_local_paseto("", None, &[0; 24], &full_key);
		if result_full.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", result_full);
			panic!("Paseto Failure Encryption!");
		}
		let the_full_str = result_full.unwrap();

		assert_eq!(
			"v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
			the_full_str
		);
	}

	#[test]
	fn paseto_non_empty_footer_encrypt_verify() {
		let empty_key = [0; 32];
		let full_key = [255; 32];

		let result = underlying_local_paseto("", Some("Cuon Alpinus"), &[0; 24], &empty_key);
		if result.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", result);
			panic!("Paseto Failure Encryption!");
		}
		let the_str = result.unwrap();

		assert_eq!(
			"v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
			the_str
		);

		let full_result = underlying_local_paseto("", Some("Cuon Alpinus"), &[0; 24], &full_key);
		if full_result.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", full_result);
			panic!("Paseto Failure Encryption!");
		}
		let full_str = full_result.unwrap();

		assert_eq!(
			"v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
			full_str
		);
	}

	#[test]
	fn paseto_non_empty_msg_encrypt_verify() {
		let empty_key = [0; 32];
		let full_key = [255; 32];

		let result = underlying_local_paseto(
			"Love is stronger than hate or fear",
			None,
			&[0; 24],
			&empty_key,
		);
		if result.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", result);
			panic!("Paseto Failure Encryption!");
		}
		let the_str = result.unwrap();

		assert_eq!(
      "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
      the_str
    );

		let full_result = underlying_local_paseto(
			"Love is stronger than hate or fear",
			None,
			&[0; 24],
			&full_key,
		);
		if full_result.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", full_result);
			panic!("Paseto Failure Encryption!");
		}

		let full_str = full_result.unwrap();

		assert_eq!(
      "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
      full_str
    );
	}

	#[test]
	fn full_round_paseto() {
		let empty_key = [0; 32];

		let result = local_paseto(
			"Love is stronger than hate or fear",
			Some("gwiz-bot"),
			&empty_key,
		);
		if result.is_err() {
			println!("Failed to encrypt Paseto!");
			println!("{:?}", result);
			panic!("Paseto Failure Encryption!");
		}
		let the_str = result.unwrap();

		println!("Paseto Full Round Token: [ {:?} ]", the_str);

		let decrypted_result = decrypt_paseto(&the_str, Some("gwiz-bot"), &empty_key);
		if decrypted_result.is_err() {
			println!("Failed to decrypt Paseto!");
			println!("{:?}", decrypted_result);
			panic!("Paseto Failure Decryption!");
		}
		let decrypted = decrypted_result.unwrap();

		assert_eq!(decrypted, "Love is stronger than hate or fear");
	}
}
