//! Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of
//! the many design deficits that plague the JOSE standards.
//!
//! # Getting Started
//!
//! The Paseto crate provides Builders which can help in the ease of building
//! tokens in an ergonomic way, these are enabled by default. However, they
//! do bring in extra dependencies on [`serde_json`], along with one of two
//! time crates [`chrono`] (the default), or if the user wants `time`.
//!
//! These can be turned on by enabling one of: `easy_tokens_chrono`, or
//! `easy_tokens_time`. While it is possible for both to be on at the same
//! time you really should only enable one. The examples below will use
//! `easy_tokens_chrono` since that is by default enabled.
//!
//! ## Creating a Token With a Builder
//!
//! Creating a token with easy tokens is done through the 'builder' pattern
//! which allows you to seemlessly build out a token, an example might be
//! as follows:
//!
//! ```
//! # #[cfg(all(feature = "easy_tokens_chrono", feature = "v2", feature = "v1", not(feature = "easy_tokens_time")))] {
//! use chrono::prelude::*;
//! use serde_json::json;
//!
//! let current_date_time = Utc::now();
//! let a_year_from_today = Utc
//!   .ymd(current_date_time.year() + 1, current_date_time.month(), current_date_time.day())
//!   .and_hms(0, 0, 0);
//!
//! let token = paseto::tokens::PasetoBuilder::new()
//!   .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
//!   .set_issued_at(None) // let's someone know when we created this token.
//!   .set_expiration(&a_year_from_today) // set this to expire in a year
//!   .set_issuer("instructure") // instructure issued this token
//!   .set_audience("witches") // this token is meant for witches
//!   .set_jti("gandalf0") // "JTI" is a jwt token id.
//!   .set_not_before(&Utc::now()) // don't let someone use this token before now.
//!   .set_subject("gandalf") // this token belongs to gandolf
//!   .set_claim("go-to", json!("mordor")) // an extra claim useful to the application
//!   .set_footer("key-id:gandalf0") // include the key-id in the footer for easy distinction.
//!   .build()
//!   .expect("Failed to encrypt token!");
//! # }
//! ```
//!
//! ## Creating a Token Without a Builder
//!
//! If you do not wish to use the builder pattern you can manually encrypt,
//! or sign a token. In this mode you are choosing directly what to stuff
//! in the body (it does not have to be JSON), as well as which particular
//! version of Paseto you're using directly.
//!
//! To know which version to choose we recommend reading:
//! <https://github.com/paragonie/paseto/blob/master/docs/Features.md>
//!
//! In this example we'll be using a `v2.local` token, but the process is
//! similar for each:
//!
//! ```
//! # #[cfg(all(feature = "easy_tokens_chrono", feature = "v2", feature = "v1", not(feature = "easy_tokens_time")))] {
//! let mut key = Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes());
//! let v2_token = paseto::v2::local::local_paseto(
//!   r#"{"my": "secret", "data": "here"}"#,
//!   Some("my-footer"),
//!   &mut key
//! ).expect("Failed to encrypt V2 Token.");
//! # }
//! ```
//!
//! Similar versions can be used such as [`v1::local::local_paseto`],
//! [`v2::public::public_paseto`], or [`v1::public::public_paseto`].
//!
//! ## Verifying a Token (With Extra Checks)
//!
//! If you're using the:
//!
//!  - Builder Pattern
//!  - JSON tokens, but have one of the build time features `easy_tokens_chrono` (on by default), or `easy_tokens_time`
//!
//! There are a series of methods that will automatically give you a JSON value,
//! and automatically validate the fields: `iat` (issued at), `exp` (expires), `nbf` (not before) for you.
//! This is in general a much *safer, and cleaner* way of validating the data within the
//! token.
//!
//! To do this you can use [`tokens::validate_local_token`], and [`tokens::validate_public_token`]
//! respectively. For example to validate the local token we created with our builder:
//!
//! ```
//! # #[cfg(all(feature = "easy_tokens_chrono", feature = "v2", feature = "v1", not(feature = "easy_tokens_time")))] {
//! # use chrono::prelude::*;
//! # use serde_json::json;
//! #
//! # let current_date_time = Utc::now();
//! # let a_year_from_today = Utc
//! #   .ymd(current_date_time.year() + 1, current_date_time.month(), current_date_time.day())
//! #   .and_hms(0, 0, 0);
//! #
//! # let token = paseto::tokens::PasetoBuilder::new()
//! #   .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
//! #   .set_issued_at(None) // let's someone know when we created this token.
//! #   .set_expiration(&a_year_from_today) // set this to expire in a year
//! #   .set_issuer("instructure") // instructure issued this token
//! #   .set_audience("witches") // this token is meant for witches
//! #   .set_jti("gandalf0") // "JTI" is a concept of JWT's and is meant to uniquely identify the token.
//! #   .set_not_before(&Utc::now()) // don't let someone use this token before now.
//! #   .set_subject("gandalf") // this token belongs to gandolf
//! #   .set_claim("go-to", json!("mordor")) // an extra claim useful to the application
//! #   .set_footer("key-id:gandalf0") // include the key-id in the footer for easy distinction.
//! #   .build()
//! #   .expect("Failed to encrypt token!");
//! #
//! let verified_token = paseto::tokens::validate_local_token(
//!   &token,
//!   Some("key-id:gandalf0"),
//!   &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
//!   &paseto::tokens::TimeBackend::Chrono,
//! )
//! .expect("Failed to validate token!");
//! # }
//! ```
//!
//! ## Decrypting/Validating Signature for a Token
//!
//! If you do not have `easy_tokens_chrono`/`easy_tokens_time` enabled, or
//! are validating something that isn't JSON. You can still use the 'direct'
//! methods but ***you own all validation of the data inside the token.*** This
//! means if you're using these methods ***it is up to you to check things like
//! expires timestamp***.
//!
//! Using the token we built above without a builder we can validate it like so:
//!
//! ```rust
//! # #[cfg(all(feature = "easy_tokens_chrono", feature = "v2", feature = "v1", not(feature = "easy_tokens_time")))] {
//! # let mut key = Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes());
//! # let v2_token = paseto::v2::local::local_paseto(r#"{"my": "secret", "data": "here"}"#, Some("my-footer"), &mut key).expect("Failed to encrypt V2 Token.");
//! #
//! let decrypted_v2_token = paseto::v2::local::decrypt_paseto(
//!   &v2_token,
//!   Some("my-footer"),
//!   &mut key
//! ).expect("Failed to decrypt V2 Token.");
//! # }
//! ```
//!
//! Again at this point the token is decrypted but is up to you, to validate it's contents.

#![recursion_limit = "128"]
#![allow(
	clippy::match_wildcard_for_single_variants,
	clippy::module_name_repetitions
)]

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
