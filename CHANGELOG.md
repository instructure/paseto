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
