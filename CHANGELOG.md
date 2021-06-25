## 2.0.2+1.0.3

* Migrate away from sodiumoxide as it has become less, and less maintained not
  providing a stable secure base anymore. Migrate to supported rust-crypto
  projects. `SodiumErrors` will keep it's name, but now represents these
  replacements for "sodium".

## 2.0.1+1.0.3

* Fix mistake where token builder would incorrectly force `nbf`/`iat`/`exp` fields.

## 2.0.0+1.0.3

* Change `pae::pae` to borrow a slice of slices (`&[&[u8]]`) instead of taking ownership of a `Vec<Vec<u8>>`.
* High-level functions like `validate_local_token` and `validate_public_token` now take the `key` by reference.
* The reference to `key` passed as argument to `v1::public::public_paseto` is not longer taken as mutable.
* `tokens::PasetoBuilder` methods have been changed to only take references
* Support for the time crate has been added with a feature, this should not be used in conjunction with chrono.
* Create better error messages to hopefully be less user hostile.
* update dependencies.
* versions now have a "build number" to indicate what upstream version they track.

## 1.0.7

* Remove `mut` from the keys used by v2/local.rs.
* Switch to taking messages, footers, and keys by reference.

## 1.0.6

* Use newer github actions.
* Remove Azure Pipelines.
* Allow TokenBuilder to just need a public key for validation.
* Make JSON Payload Validation public so anyone can use it.

## 1.0.5

* Upgrade Ring

## 1.0.4

* Start running CI on Macs.
* Start running CI on nightly/beta builds.
* Start running CI every night.
* Upgrade openssl.
* Upgrade Ring.
* Remove direct dependency on untrusted.

## 1.0.3

* Bump Dependencies to latest version.
* Sodiumoxide segfault on mac-os-x has been fixed.

## 1.0.2

* Bump Dependencies to latest versions.
* Use sodiumoxide over libsodium_ffi directly. (no more unsafe \o/)
* Update to rust 2018 epoch.
* Can no longer export `SODIUM_BUILD_STATIC`, and `SODIUM_STATIC`

## 1.0.1

* Bump Dependencies to latest versions.
* Remove some unneeded crypto crates to lower total surface area of attack.
* Allow V2 Public to just accept public key bytes.
* Ensure all tests still pass.

## 0.5.0

* Initial Public Release
