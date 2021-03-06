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
  #[fail(display = "Failed to generate signed RSA content")]
  SignError {},
}

#[derive(Debug, Fail)]
pub enum GenericError {
  #[fail(display = "No key of the correct type was provided")]
  NoKeyProvided {},
  #[fail(display = "This token is invalid.")]
  InvalidToken {},
  #[fail(display = "The claim: {}, has an invalid date", claim_name)]
  UnparseableTokenDate { claim_name: &'static str },
  #[fail(display = "This token has not yet been issued, the issued at claim (IAT) is in the future.")]
  InvalidIssuedAtToken {},
  #[fail(display = "This token is not valid yet (NBF claim).")]
  InvalidNotBeforeToken {},
  #[fail(display = "This token is expired (EXP claim).")]
  ExpiredToken {},
  #[fail(display = "This token has an invalid footer.")]
  InvalidFooter {},
  #[fail(display = "Failed to generate enough random bytes.")]
  RandomError {},
  #[fail(display = "Failed to perform HKDF")]
  BadHkdf {},
}
