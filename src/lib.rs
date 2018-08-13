#![recursion_limit = "128"]

extern crate base64;
#[cfg(feature = "easy_tokens")]
extern crate chrono;
#[macro_use]
extern crate error_chain;
#[cfg(feature = "v2")]
extern crate libsodium_ffi as libsodium;
#[cfg(feature = "v1")]
extern crate openssl;
extern crate ring;
#[cfg(feature = "easy_tokens")]
#[macro_use]
extern crate serde_json;
extern crate untrusted;

#[cfg(test)]
extern crate hex;

pub mod errors;
pub mod pae;

#[cfg(feature = "v2")]
mod sodium;
#[cfg(feature = "easy_tokens")]
pub mod tokens;
#[cfg(feature = "easy_tokens")]
pub use self::tokens::*;
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;
