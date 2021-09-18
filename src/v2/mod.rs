//! ["Direct" use of Protocol for V2 of Paseto.](https://github.com/paseto-standard/paseto-spec/blob/8b3fed8240e203b058649d01a82a8c412087bc87/docs/01-Protocol-Versions/Version2.md)
//!
//! It is recommended to use the easy tokens, which are present in the
//! [`crate::tokens`] module. As it automatically can validate things like
//! expirey time, however the direct protocol allows you to encode arbitrary
//! data which can be beneficial.
//!
//! Local Encryption Methods:
//!   - [`self::local_paseto`] / [`self::decrypt_paseto`]
//!
//! Public Signing Methods:
//!   - [`self::public_paseto`] / [`self::verify_paseto`]

pub mod local;
pub mod public;
pub use self::local::*;
pub use self::public::*;
