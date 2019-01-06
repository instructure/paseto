#![recursion_limit = "128"]

pub mod errors;
pub mod pae;

#[cfg(feature = "easy_tokens")]
pub mod tokens;
#[cfg(feature = "easy_tokens")]
pub use self::tokens::*;
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;
