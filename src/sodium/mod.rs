use libsodium;

use std::sync::atomic::AtomicBool;

pub mod aead;
pub mod hash;

pub static IS_LIBSODIUM_INTIALIZED: AtomicBool = AtomicBool::new(false);

/// `init_sodium()` initializes the sodium library and chooses faster versions of
/// the primitives if possible. `init()` also makes the random number generation
/// functions (`gen_key`, `gen_keypair`, `gen_nonce`, `randombytes`, `randombytes_into`)
/// thread-safe
///
/// `init_sodium()` returns `Ok` if initialization succeeded and `Err` if it failed.
pub fn init_sodium() -> Result<(), ()> {
  if unsafe { libsodium::sodium_init() } >= 0 {
    Ok(())
  } else {
    Err(())
  }
}
