use chrono::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde_json::json;

fn main() {
  let current_date_time = Utc::now();
  let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

  let sys_rand = SystemRandom::new();
  let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
  let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
  let cloned_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

  let token = paseto::tokens::PasetoBuilder::new()
    .set_ed25519_key(as_key)
    .set_issued_at(None)
    .set_expiration(dt)
    .set_issuer(String::from("instructure"))
    .set_audience(String::from("wizards"))
    .set_jti(String::from("gandalf0"))
    .set_not_before(Utc::now())
    .set_subject(String::from("gandalf"))
    .set_claim(String::from("go-to"), json!(String::from("mordor")))
    .set_footer(String::from("key-id:gandalf0"))
    .build()
    .expect("Failed to construct paseto token w/ builder!");
  println!("{:?}", token);

  let verified_token = paseto::tokens::validate_public_token(
    token,
    Some(String::from("key-id:gandalf0")),
    paseto::tokens::PasetoPublicKey::ED25519KeyPair(cloned_key),
  )
  .expect("Failed to validate token!");
  println!("{:?}", verified_token);
}
