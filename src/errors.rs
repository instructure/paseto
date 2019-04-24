use failure_derive::*;

#[derive(Debug, Fail)]
pub enum SodiumErrors {
  #[fail(display = "invalid key size, needed: {} got: {}", size_needed, size_provided)]
  InvalidKeySize { size_provided: usize, size_needed: usize },
  #[fail(display = "invalid nonce size, needed: {} got: {}", size_needed, size_provided)]
  InvalidNonceSize { size_provided: usize, size_needed: usize },
  #[fail(display = "Invalid key for libsodium!")]
  InvalidKey {},
  #[fail(display = "Function call to C Sodium Failed.")]
  FunctionError {},
  #[fail(display = "Invalid Output Size specified")]
  InvalidOutputSize {},
}

#[derive(Debug, Fail)]
pub enum RsaKeyErrors {
  #[fail(display = "Invalid RSA Key Provided")]
  InvalidKey {},
}

#[derive(Debug, Fail)]
pub enum GenericError {
  #[fail(display = "No key of the correct type was provided")]
  NoKeyProvided {},
  #[fail(display = "This token is invalid, or expired.")]
  InvalidToken {},
  #[fail(display = "This token has an invalid footer.")]
  InvalidFooter {},
}
