use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasetoError {
	#[cfg(any(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
	#[error(transparent)]
	JsonError(#[from] serde_json::Error),
	#[error(transparent)]
	GenericError(#[from] GenericError),
	#[error(transparent)]
	LibsodiumError(#[from] SodiumErrors),
	#[cfg(feature = "v1")]
	#[error(transparent)]
	OpensslError(#[from] openssl::error::ErrorStack),
	#[error(transparent)]
	RsaError(#[from] RsaKeyErrors),
}

#[derive(Debug, Error)]
pub enum SodiumErrors {
	#[error("invalid key size, needed: {} got: {}", size_needed, size_provided)]
	InvalidKeySize {
		size_provided: usize,
		size_needed: usize,
	},
	#[error("invalid nonce size, needed: {} got: {}", size_needed, size_provided)]
	InvalidNonceSize {
		size_provided: usize,
		size_needed: usize,
	},
	#[error("Invalid key for libsodium!")]
	InvalidKey {},
	#[error("Function call to C Sodium Failed.")]
	FunctionError {},
	#[error("Invalid Output Size specified")]
	InvalidOutputSize {},
}

#[derive(Debug, Error)]
pub enum RsaKeyErrors {
	#[error("Invalid RSA Key Provided")]
	InvalidKey {},
	#[error("Failed to generate signed RSA content")]
	SignError {},
}

#[derive(Debug, Error)]
pub enum GenericError {
	#[error("Failed to perform HKDF")]
	BadHkdf {},
	#[error(transparent)]
	Base64Error(#[from] base64::DecodeError),
	#[error("This token is expired (EXP claim).")]
	ExpiredToken {},
	#[error("This token has an invalid footer.")]
	InvalidFooter {},
	#[error("This token has not yet been issued, the issued at claim (IAT) is in the future.")]
	InvalidIssuedAtToken {},
	#[error("This token is not valid yet (NBF claim).")]
	InvalidNotBeforeToken {},
	#[error("This token is invalid.")]
	InvalidToken {},
	#[error("No key of the correct type was provided")]
	NoKeyProvided {},
	#[error("Failed to generate enough random bytes.")]
	RandomError {},
	#[error(transparent)]
	Utf8Error(#[from] std::string::FromUtf8Error),
	#[error("The claim: {}, has an invalid date", claim_name)]
	UnparseableTokenDate { claim_name: &'static str },
}
