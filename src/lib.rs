#![recursion_limit = "128"]

pub mod errors;
pub mod pae;

#[cfg(any(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
pub mod tokens;
#[cfg(any(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
pub use self::tokens::*;
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;
