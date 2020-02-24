use thiserror::Error;

#[derive(Error, Debug)]
pub enum SodiumErrors {
  #[error("Invalid key for libsodium!")]
  InvalidKey,
  #[error("Function call to C Sodium Failed.")]
  FunctionError,
}

#[derive(Error, Debug)]
pub enum RsaKeyErrors {
  #[error("Invalid RSA Key Provided")]
  InvalidKey(#[from] ring::error::KeyRejected),
  #[error("Invalid modulus size, expected {} but got {}", expected, actual)]
  InvalidModulusSize {
    expected: usize,
    actual: usize,
  },
  #[error("Failed to generate signed RSA content")]
  SignError,
}

#[derive(Error, Debug)]
pub enum GenericError {
  #[error("No key of the correct type was provided")]
  NoKeyProvided,
  #[error("This token is invalid, or expired.")]
  InvalidToken,
  #[error("This token has an invalid footer.")]
  InvalidFooter,
  #[error("Failed to generate enough random bytes.")]
  RandomError,
  #[error("Failed to perform HKDF")]
  BadHkdf,
  #[error("JSON serialization error: {0}")]
  JsonSerializationError(#[from] serde_json::error::Error),
  #[error("RSA key error: {0}")]
  RsaKeyError(#[from] RsaKeyErrors),
  #[error("Sodium error: {0}")]
  SodiumErrors(#[from] SodiumErrors),
  #[error("Invalid UTF-8: {0}")]
  InvalidUtf8(#[from] std::string::FromUtf8Error),
  #[error("Base64 decoding failed: {0}")]
  Base64DecodeError(#[from] base64::DecodeError),
  #[error("OpenSSL error: {0}")]
  OpenSslError(#[from] openssl::error::ErrorStack),
}