#[cfg(all(feature = "v2", feature = "easy_tokens"))]
use {
  chrono::prelude::*,
  ring::rand::SystemRandom,
  ring::signature::Ed25519KeyPair,
  serde_json::json,
};

fn main() {
  #[cfg(all(feature = "v2", feature = "easy_tokens"))]
  {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let sys_rand = SystemRandom::new();
    let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
    let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

    let token = paseto::tokens::PasetoBuilder::new()
      .set_ed25519_key(&as_key)
      .set_issued_at(None)
      .set_expiration(&dt)
      .set_issuer("instructure")
      .set_audience("wizards")
      .set_jti("gandalf0")
      .set_not_before(&Utc::now())
      .set_subject("gandalf")
      .set_claim("go-to", json!("mordor"))
      .set_footer("key-id:gandalf0")
      .build()
      .expect("Failed to construct paseto token w/ builder!");
    println!("{:?}", token);

    let verified_token = paseto::tokens::validate_public_token(
      &token,
      Some("key-id:gandalf0"),
    &paseto::tokens::PasetoPublicKey::ED25519KeyPair(&as_key),
    )
    .expect("Failed to validate token!");

    println!("{:?}", verified_token);
  }
}
