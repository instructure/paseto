//! A package that contains all of the error types this crate is capable of
//! producing.

use thiserror::Error;

/// The 'top-level' error that each function will return, this is just here to
/// give us one consistent return type.
#[derive(Debug, Error)]
pub enum PasetoError {
	#[cfg(any(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
	#[error(transparent)]
	/// An error re-exported from the `serde_json` crate.
	JsonError(#[from] serde_json::Error),
	#[error(transparent)]
	/// There was an error that was just a generic paseto error, not speciifc
	/// to any library or encryption.
	GenericError(#[from] GenericError),
	#[error(transparent)]
	/// There was an error interacting with libsodium.
	LibsodiumError(#[from] SodiumErrors),
	#[cfg(feature = "v1")]
	#[error(transparent)]
	/// There was an error interacting with OpenSSL.
	OpensslError(#[from] openssl::error::ErrorStack),
	#[error(transparent)]
	/// There was an error related to RSA key parsing.
	RsaError(#[from] RsaKeyErrors),
}

/// There was an error interacting with libsodium.
#[derive(Debug, Error)]
pub enum SodiumErrors {
	/// A libsodium algorithim was expecting a key of a certain size, but did
	/// not receive it.
	#[error("invalid key size, needed: {} got: {}", size_needed, size_provided)]
	InvalidKeySize {
		size_provided: usize,
		size_needed: usize,
	},
	/// A libsodium algorithim was expecting a nonce of a certain size, but did
	/// not receive it.
	#[error("invalid nonce size, needed: {} got: {}", size_needed, size_provided)]
	InvalidNonceSize {
		size_provided: usize,
		size_needed: usize,
	},
	/// the libsodium algorithim let us know the key was invalid with no extra info.
	#[error("Invalid key for libsodium!")]
	InvalidKey {},
	/// A C function from libsodium we never expect to fail, failed.
	#[error("Function call to C Sodium Failed.")]
	FunctionError {},
	/// libsodium expected to write a certain number of bytes out, but
	/// couldn't write because it was too small or too large.
	#[error("Invalid Output Size specified")]
	InvalidOutputSize {},
}

/// There was an error roughly related to the RSA Key input.
#[derive(Debug, Error)]
pub enum RsaKeyErrors {
	/// The user provided key could not be parsed as DER.
	#[error("Invalid RSA Key Provided")]
	InvalidKey {},
	/// We could not sign the data using the key provided.
	#[error("Failed to generate signed RSA content")]
	SignError {},
}

/// Any errors that are generic to the whole crate.
#[derive(Debug, Error)]
pub enum GenericError {
	/// We failed to create a key with hmac's or HKDF.
	#[error("Failed to perform HKDF")]
	BadHkdf {},
	/// An error re-exported from the base64 crate.
	#[error(transparent)]
	Base64Error(#[from] base64::DecodeError),
	/// While validating a token we noticed it was expired.
	#[error("This token is expired (EXP claim).")]
	ExpiredToken {},
	/// While validating a token we expected a specific footer, but noticed
	/// it was not correct.
	#[error("This token has an invalid footer.")]
	InvalidFooter {},
	/// While validating a token we noticed the issued at timestamp was in
	/// the future meaning it has not yet been issued.
	#[error("This token has not yet been issued, the issued at claim (IAT) is in the future.")]
	InvalidIssuedAtToken {},
	/// While validating a token, the not before claim was in the future,
	/// which means the token cannot yet be used.
	#[error("This token is not valid yet (NBF claim).")]
	InvalidNotBeforeToken {},
	/// While attempting to validate a token we could not parse/decrypt/validate the signature
	/// of the token.
	#[error("This token is invalid.")]
	InvalidToken {},
	/// While using the 'easy' token builder pattern you failed
	/// to provide a key that could be used given your compile time
	/// options.
	#[error("No key of the correct type was provided")]
	NoKeyProvided {},
	/// We failed generating the amount of random bytes that we needed.
	#[error("Failed to generate enough random bytes.")]
	RandomError {},
	/// Re-Exporting a string from utf8 error.
	#[error(transparent)]
	Utf8Error(#[from] std::string::FromUtf8Error),
	/// We expected a datetime in a specific claim but failed to parse the data
	/// as a date.
	#[error("The claim: {}, has an invalid date", claim_name)]
	UnparseableTokenDate { claim_name: &'static str },
}
