use errors::*;

use libsodium::crypto_generichash;

use std::os::raw::c_uchar;
use std::slice::from_raw_parts_mut;
use std::ptr as c_ptr;

/// Calls LibSodiums crypto generic hash.
#[allow(unused_assignments)]
pub fn crypto_generic_hash(to_hash: &[u8], key_bytes: Option<&[u8]>, outlen: usize) -> Result<Vec<u8>> {
  // The actual function for crypto_generichash looks like:
  //
  // ```rust
  // pub unsafe extern "C" fn crypto_generichash(
  //   out: *mut c_uchar,
  //   outlen: size_t,
  //   in_: *const c_uchar,
  //   inlen: c_ulonglong,
  //   key: *const c_uchar,
  //   keylen: size_t
  // ) -> c_int
  // ```
  //
  // Since these variable names are taken straight from libsodium (and don't mean anything to
  // those who haven't used libsodium before let me reach into their docs for this function
  // and explain what they mean).
  //
  // out -> the output of the hash function.
  // outlen -> the length of output (can be chosen by app). As long as it's >16 and <128.
  // in_ -> the input data to hash.
  // inlen -> the length of the input data.
  // key -> the optional key to use. otherwise is nullptr.
  // keylen -> the length of the optional key, 0 if there is none.

  if outlen < 16 || outlen > 64 {
    return Err(ErrorKind::InvalidOutputSize.into());
  }

  let mut keylen = 0 as usize;
  let mut key_data: Vec<u8> = Vec::new();
  let key = if key_bytes.is_some() {
    // Must turn it into a vec first, otherwise we get an unrecoverable error.
    let the_key = key_bytes.unwrap();
    keylen = the_key.len();
    key_data = Vec::from(the_key);
    key_data.as_slice().as_ptr()
  } else {
    c_ptr::null()
  };

  let inlen = to_hash.len() as u64;
  let in_ = to_hash.as_ptr();

  let mut out_vec: Vec<u8> = Vec::with_capacity(outlen);
  let out: *mut c_uchar = out_vec.as_mut_slice().as_mut_ptr();

  let res_code: i32 = unsafe { crypto_generichash(out, outlen, in_, inlen, key, keylen) };
  if res_code != 0 {
    return Err(ErrorKind::LibSodiumError.into());
  }
  let slice: &[u8] = unsafe { from_raw_parts_mut(out, outlen) };

  Ok(Vec::from(slice))
}

#[cfg(test)]
mod unit_tests {
  use super::*;
  use sodium::init_sodium;

  #[test]
  fn test_blake2_hash() {
    // Constants compared against rbnacl.
    let _ = init_sodium();
    let hashed = crypto_generic_hash("test".to_owned().as_bytes(), None, 64);
    if hashed.is_err() {
      println!("Failed to hash data!");
      println!("{:?}", hashed);
      panic!("Hash failed!");
    }
    let as_hash = hashed.unwrap();
    println!("Hash: [ {:?} ]", as_hash);

    assert_eq!(
      as_hash,
      vec![
        167, 16, 121, 212, 40, 83, 222, 162, 110, 69, 48, 4, 51, 134, 112, 165, 56, 20, 183, 129, 55, 255, 190, 208,
        118, 3, 164, 29, 118, 164, 131, 170, 155, 195, 59, 88, 47, 119, 211, 10, 101, 230, 242, 154, 137, 108, 4, 17,
        243, 131, 18, 225, 214, 110, 11, 241, 99, 134, 200, 106, 137, 190, 165, 114,
      ]
    );
  }

  #[test]
  fn test_blake2_keyed_hash() {
    // Constants compared against rbnacl.
    let _ = init_sodium();
    let hashed = crypto_generic_hash(
      "test".to_owned().as_bytes(),
      Some("testtesttesttest".to_owned().as_bytes()),
      64,
    );
    if hashed.is_err() {
      println!("Failed to hash data!");
      println!("{:?}", hashed);
      panic!("Hash failed!");
    }
    let as_hash = hashed.unwrap();
    println!("Keyed Hash: [ {:?} ]", as_hash);

    assert_eq!(
      as_hash,
      vec![
        54, 140, 60, 165, 217, 21, 90, 217, 242, 94, 185, 109, 171, 122, 207, 170, 75, 84, 28, 65, 1, 212, 233, 31,
        136, 226, 82, 202, 207, 2, 252, 212, 6, 229, 153, 82, 26, 118, 49, 205, 233, 216, 238, 127, 18, 226, 60, 178,
        16, 173, 224, 4, 93, 173, 88, 176, 84, 159, 131, 59, 214, 133, 210, 18,
      ]
    );
  }
}
