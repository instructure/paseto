//! Wraps all of our individual errors out as one type,
//! so we return a consistent error type across everything.
//!
//! This would also allow us to wrap errors if they ever give us a less
//! than ideal message.

use base64;
use ring;

use std::ffi::{IntoStringError, NulError};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

error_chain! {

  foreign_links {
    Base64DecodeError(base64::DecodeError);
    FfiNulError(NulError);
    FfiStringError(IntoStringError);
    IoOperationError(IoError);
    RingError(ring::error::Unspecified);
    UtfStrError(Utf8Error);
    UtfStringError(FromUtf8Error);
  }

  errors {
    HmacError {
      description("There was an underlying hmac error!")
      display("There was an underlying hmac error!")
    }

    InvalidKey {
      description("You passed in a ED25519 key for a V1 token, or a RSA key for a V2 Token!")
      display("You passed in a ED25519 key for a V1 token, or a RSA key for a V2 Token!")
    }

    InvalidKeySize(size: u32, needed_size: u32) {
      description("The size for this key does not match what libsodium needs!")
      display("The key of size: {} that was passed in is not the size: {} needed by libsodium!", size, needed_size)
    }

    InvalidNonceSize(size: u32, needed_size: u32) {
      description("The size of this nonce does not match what libsodium needs!")
      display("The nonce of size: {} was not the size: {} needed by libsodium!", size, needed_size)
    }

    InvalidNonce {
      description("This is an invalid nonce with signature!")
      display("This is an invalid nonce with signature!")
    }

    InvalidOutputSize {
      description("Invalid output size specified for hash.")
      display("Invalid output size specified for a hash.")
    }

    InvalidPasetoFooter {
      description("This Paseto has an invalid footer.")
      display("This Paseto has an invalid footer attached. Cannot decrypt.")
    }

    InvalidPasetoToken {
      description("We were passed in an invalid Paseto to decrypt")
      display("This Paseto has been corrupted in some way. Cannot decrypt.")
    }

    InvalidRsaKeySize(size: u32, your_size: usize) {
      description("This is an invalid rsa key size!")
      display("This paseto token calls for an RSA Key Size of: {}, you passed in one with: {}.", size, your_size)
    }

    InvalidRsaKey {
      description("A non-der RSA Private Key was passed in!")
      display("A non-der RSA Private Key was passed in!")
    }

    JsonError {
      description("Failure serializing your claims json!")
      display("Failure serializing your claims json!")
    }

    LibSodiumError {
      description("Failed to interact with libsodium!")
      display("We have failed to interact with libsodium!")
    }

    NoKeysProvided {
      description("You created a builder instance but provided no keys for encreyption/signing!")
      display("You created a builder instance but provided no keys for encreyption/signing!")
    }

    OpensslError {
      description("There was an underlying openssl error!")
      display("There was an underlying error with openssl.")
    }
  }

}
