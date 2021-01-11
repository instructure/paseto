fn main() {
  let key = "YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes();
  let mut key_mut = Vec::from(key);
  let message = "This is a signed non-JSON message.";
  let footer = "key-id:gandalf0";

  #[cfg(feature = "v1")]
  {
    // Version 1
    let v1_token =
      paseto::v1::local::local_paseto(&message, None, key).expect("Failed to encrypt V1 Token sans footer.");
    println!("{:?}", v1_token);
    let decrypted_v1_token =
      paseto::v1::local::decrypt_paseto(&v1_token, None, key).expect("Failed to decrypt V1 Token sans footer.");
    println!("{:?}", decrypted_v1_token);
    let v1_footer_token =
      paseto::v1::local::local_paseto(&message, Some(&footer), key).expect("Failed to encrypt V1 Token.");
    println!("{:?}", v1_footer_token);
    let decrypted_v1_footer_token =
      paseto::v1::local::decrypt_paseto(&v1_footer_token, Some(&footer), key).expect("Failed to decrypt V1 Token.");
    println!("{:?}", decrypted_v1_footer_token);
  }

  #[cfg(feature = "v2")]
  {
    // Version 2
    let v2_token =
      paseto::v2::local::local_paseto(&message, None, &mut key_mut).expect("Failed to encrypt V2 Token sans footer.");
    println!("{:?}", v2_token);
    let decrypted_v2_token = paseto::v2::local::decrypt_paseto(&v2_token, None, &mut key_mut)
      .expect("Failed to decrypt V2 Token sans footer.");
    println!("{:?}", decrypted_v2_token);
    let v2_footer_token =
      paseto::v2::local::local_paseto(&message, Some(&footer), &mut key_mut).expect("Failed to encrypt V2 Token.");
    println!("{:?}", v2_footer_token);
    let decrypted_v2_footer = paseto::v2::local::decrypt_paseto(&v2_footer_token, Some(&footer), &mut key_mut)
      .expect("Failed to decrypt V2 Token.");
    println!("{:?}", decrypted_v2_footer);
  }
}
