## Unreleased

* Change `pae::pae` to borrow a slice of slices (`&[&[u8]]`) instead of taking ownership of a `Vec<Vec<u8>>`.
* High-level functions like `validate_local_token` and `validate_public_token` now take the `key` by reference.

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
