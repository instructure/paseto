use thiserror::Error;

/// A trait to easily convert sodium errors that are of the unit type
/// to `SodiumErrors::FunctionError`.
#[cfg(feature = "v2")]
pub(crate) trait SodiumResult<T> {
  /// Convert sodium errors that are of the unit type
  /// to `SodiumErrors::FunctionError`.
  fn map_sodium_err(self) -> Result<T, SodiumErrors>;
}

#[cfg(feature = "v2")]
impl<T> SodiumResult<T> for Result<T, ()> {
  #[inline]
  fn map_sodium_err(self) -> Result<T, SodiumErrors> {
    self.map_err(SodiumErrors::FunctionError)
  }
}

#[cfg(feature = "v2")]
#[derive(Error, Debug)]
pub enum SodiumErrors {
  #[error("Invalid key for libsodium!")]
  InvalidKey,
  #[error("Function call to C Sodium Failed.")]
  FunctionError(()),
}

#[cfg(feature = "v1")]
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
  SignError(#[source] ring::error::Unspecified),
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
  RandomError(#[source] ring::error::Unspecified),
  #[error("Failed to perform HKDF")]
  BadHkdf(#[source] ring::error::Unspecified),
  #[cfg(feature = "easy_tokens")]
  #[error("JSON serialization error: {0}")]
  JsonSerializationError(#[from] serde_json::error::Error),
  #[cfg(feature = "v1")]
  #[error("RSA key error: {0}")]
  RsaKeyError(#[from] RsaKeyErrors),
  #[cfg(feature = "v2")]
  #[error("Sodium error: {0}")]
  SodiumErrors(#[from] SodiumErrors),
  #[error("Invalid UTF-8: {0}")]
  InvalidUtf8(#[from] std::string::FromUtf8Error),
  #[error("Base64 decoding failed: {0}")]
  Base64DecodeError(#[from] base64::DecodeError),
  #[cfg(feature = "v1")]
  #[error("OpenSSL error: {0}")]
  OpenSslError(#[from] openssl::error::ErrorStack),
}