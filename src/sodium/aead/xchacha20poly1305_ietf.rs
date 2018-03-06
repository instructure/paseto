use errors::*;
use libsodium::{crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt};

use std::os::raw::{c_uchar, c_ulonglong};
use std::slice::from_raw_parts_mut;
use std::ptr as c_ptr;
use std::str::from_utf8 as ParseUtf8;

/// Encrypt a message using xchacha20poly1305-ietf.
///
/// `msg`: The Message to encrypt.
/// `extra_data`: The extra data to attach into the message.
/// `nonce`: The Nonce to use. (must be 24 bytes).
/// `key_bytes`: The Key to use. (must be 32 bytes).
#[allow(unused_assignments)]
pub fn xchacha20poly1305_ietf_encrypt(
  msg: String,
  extra_data: Option<Vec<u8>>,
  nonce: &mut [u8],
  key_bytes: &mut [u8],
) -> Result<Vec<u8>> {
  // The actual function for crypto_aead_xchacha20poly1305_ietf_encrypt looks like:
  //
  // ```rust
  // pub unsafe extern "C" fn crypto_aead_xchacha20poly1305_ietf_encrypt(
  //   c: *mut c_uchar,
  //   clen_p: *mut c_ulonglong,
  //   m: *const c_uchar,
  //   mlen: c_ulonglong,
  //   ad: *const c_uchar,
  //   adlen: c_ulonglong,
  //   nsec: *const c_uchar,
  //   npub: *const c_uchar,
  //   k: *const c_uchar
  // ) -> c_int
  // ```
  //
  // Since these variable names are taken straight from libsodium (and don't mean anything to
  // those who haven't used libsodium before let me reach into their docs for this function
  // and explain what they mean).
  //
  // m -> the message to encrypt
  // mlen -> the length of the message to encrypt (gotta love c and pointers).
  // k -> The key to encrypt with, must have a length equal to: crypto_aead_xchacha20poly1305_ietf_KEYBYTES (32)
  // npub -> The nonce to use with this message, should always be unique. Use OsRng to generate random bytes in Rust.
  // ad -> any "non-confidential data" to include. (can be nullptr).
  // adlen -> the length of ad if there is one, or a zero.
  // c -> The resulting crypted text if successful.
  // clen_p -> `At most mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES (16)` actual result stored here.
  // nsec -> `nsec is not used by this particular construction, and should always be NULL.`

  if key_bytes.len() != 32 {
    return Err(ErrorKind::InvalidKeySize(key_bytes.len() as u32, 32).into());
  }
  if nonce.len() != 24 {
    return Err(ErrorKind::InvalidNonceSize(nonce.len() as u32, 24).into());
  }

  let nsec = c_ptr::null();
  let npub = nonce.as_mut_ptr();

  let k = key_bytes.as_mut_ptr();

  let mlen = msg.len() as u64;
  let m: *mut c_uchar = msg.into_bytes().as_mut_slice().as_mut_ptr();

  let clen_p: *mut c_ulonglong = (&mut ((mlen + 16) as u64)) as *mut c_ulonglong;
  let mut c_vec: Vec<u8> = Vec::with_capacity(mlen as usize + 16);
  let c: *mut c_uchar = c_vec.as_mut_slice().as_mut_ptr();

  // Split this up so the pointer to the extra data lives longer than the pointer to it.
  let mut ad_len = 0 as u64;
  let mut ead: Vec<u8> = Vec::new();
  let ad = if extra_data.is_some() {
    let the_data = extra_data.unwrap();
    ad_len = the_data.len() as u64;
    ead = the_data;
    ead.as_mut_slice().as_mut_ptr()
  } else {
    c_ptr::null()
  };

  let res_code: i32 =
    unsafe { crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, ad_len, nsec, npub, k) };
  if res_code != 0 {
    return Err(ErrorKind::LibSodiumError.into());
  }
  let slice: &[u8] = unsafe { from_raw_parts_mut(c, (*clen_p) as usize) };

  let res = Vec::from(slice);
  Ok(res)
}

/// Decrypt a message using xchacha20poly1305-ietf.
///
/// `ciphertext`: The Message to decrypt.
/// `extra_data`: The extra data to attach into the message.
/// `nonce`: The Nonce to use. (must be 24 bytes).
/// `key_bytes`: The Key to use. (must be 32 bytes).
#[allow(unused_assignments)]
pub fn xchacha20poly1305_ietf_decrypt(
  mut ciphertext: Vec<u8>,
  extra_data: Option<Vec<u8>>,
  nonce: &mut [u8],
  key_bytes: &mut [u8],
) -> Result<String> {
  // The actual function for crypto_aead_xchacha20poly1305_ietf_encrypt looks like:
  //
  // ```rust
  // pub unsafe extern "C" fn crypto_aead_xchacha20poly1305_ietf_decrypt(
  //   m: *mut c_uchar,
  //   mlen_p: *mut c_ulonglong,
  //   nsec: *mut c_uchar,
  //   c: *const c_uchar,
  //   clen: c_ulonglong,
  //   ad: *const c_uchar,
  //   adlen: c_ulonglong,
  //   npub: *const c_uchar,
  //   k: *const c_uchar
  // ) -> c_int
  // ```
  //
  // Since these variable names are taken straight from libsodium (and don't mean anything to
  // those who haven't used libsodium before let me reach into their docs for this function
  // and explain what they mean).
  //
  // m -> The Decrypted message if successful.
  //   `At most clen - crypto_aead_xchacha20poly1305_ietf_ABYTES (16) bytes will be put into m.`.
  // mlen_p -> The actual length of the decrypted message.
  // nsec -> `nsec is not used by this particular construction, and should always be NULL.`
  // c -> The Cipher Text.
  // clen -> The length of ciphertext.
  // ad -> the extra data or a nullptr.
  // adlen -> the length of the extra data.
  // npub -> the nonce to use.
  // k -> the key to use.

  if key_bytes.len() != 32 {
    return Err(ErrorKind::InvalidKeySize(key_bytes.len() as u32, 32).into());
  }
  if nonce.len() != 24 {
    return Err(ErrorKind::InvalidNonceSize(nonce.len() as u32, 24).into());
  }

  let nsec = c_ptr::null_mut();
  let npub = nonce.as_mut_ptr();

  let k = key_bytes.as_mut_ptr();

  let clen = ciphertext.len() as u64;
  let c: *mut c_uchar = ciphertext.as_mut_slice().as_mut_ptr();

  let mut max_len = clen as usize;
  if max_len > 16 {
    max_len = max_len - 16;
  }
  let mlen_p: *mut c_ulonglong = (&mut ((max_len) as u64)) as *mut c_ulonglong;
  let mut m_vec: Vec<u8> = Vec::with_capacity(max_len);
  let m: *mut c_uchar = m_vec.as_mut_slice().as_mut_ptr();

  // Split this up so the pointer to the extra data lives longer than the pointer to it.
  let mut ad_len = 0 as u64;
  let mut ead: Vec<u8> = Vec::new();
  let ad = if extra_data.is_some() {
    let the_data = extra_data.unwrap();
    ad_len = the_data.len() as u64;
    ead = the_data;
    ead.as_mut_slice().as_mut_ptr()
  } else {
    c_ptr::null()
  };

  let res_code: i32 =
    unsafe { crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, ad_len, npub, k) };
  if res_code != 0 {
    return Err(ErrorKind::LibSodiumError.into());
  }
  let slice: &[u8] = unsafe { from_raw_parts_mut(m, (*mlen_p) as usize) };
  let as_str = try!(ParseUtf8(slice));

  Ok(as_str.to_owned())
}

#[cfg(test)]
mod unit_tests {
  use super::*;
  use sodium::init_sodium;

  #[test]
  fn test_full_round_encryption() {
    let _ = init_sodium();
    let mut nonce = [0; 24];
    let encrypted_text = xchacha20poly1305_ietf_encrypt(
      String::from("test message"),
      None,
      &mut nonce,
      String::from("testtesttesttesttesttesttesttest")
        .into_bytes()
        .as_mut_slice(),
    );
    if encrypted_text.is_err() {
      println!("Failed to encrypt test message!");
      println!("{:?}", encrypted_text);
      panic!("Failed to encrypt");
    }
    let e_text = encrypted_text.unwrap();

    println!("Encrypted Text: [ {:?} ]", e_text);

    let decrypted_text = xchacha20poly1305_ietf_decrypt(
      e_text,
      None,
      &mut nonce,
      String::from("testtesttesttesttesttesttesttest")
        .into_bytes()
        .as_mut_slice(),
    );
    if decrypted_text.is_err() {
      println!("Failed to decrypt test message!");
      println!("{:?}", decrypted_text);
      panic!("Failed to decrypt!");
    }
    let d_text = decrypted_text.unwrap();

    println!("Decrypted Text: [ {:?} ]", d_text);
    assert_eq!(d_text, "test message");
  }

  #[test]
  fn test_full_round_aad() {
    let _ = init_sodium();
    let mut nonce = [0; 24];
    let encrypted_text = xchacha20poly1305_ietf_encrypt(
      String::from("test message"),
      Some(Vec::from(
        String::from("\u{1}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{4}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}test").as_bytes(),
      )),
      &mut nonce,
      String::from("testtesttesttesttesttesttesttest")
        .into_bytes()
        .as_mut_slice(),
    );
    if encrypted_text.is_err() {
      println!("Failed to encrypt test message!");
      println!("{:?}", encrypted_text);
      panic!("Failed to encrypt");
    }
    let e_text = encrypted_text.unwrap();

    println!("Encrypted Text: {:?}", e_text);

    let decrypted_failure_text = xchacha20poly1305_ietf_decrypt(
      e_text.clone(),
      Some(Vec::from(String::from("bleh").as_bytes())),
      &mut nonce,
      String::from("testtesttesttesttesttesttesttest")
        .into_bytes()
        .as_mut_slice(),
    );
    if decrypted_failure_text.is_ok() {
      println!("{:?}", decrypted_failure_text);
      panic!("Decrypted text without proper ad successfully decrypted!");
    }

    let decrypted_text = xchacha20poly1305_ietf_decrypt(
      e_text,
      Some(Vec::from(
        String::from("\u{1}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{4}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}test").as_bytes(),
      )),
      &mut nonce,
      String::from("testtesttesttesttesttesttesttest")
        .into_bytes()
        .as_mut_slice(),
    );
    if decrypted_text.is_err() {
      println!("Failed to decrypt text!");
      println!("{:?}", decrypted_text);
      panic!("Failed to decrypt with aad");
    }
    let d_text = decrypted_text.unwrap();

    println!("Decrypted Text: {:?}", d_text);
    assert_eq!(d_text, "test message");
  }
}
