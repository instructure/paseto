#[cfg(feature = "easy_tokens")]
use {
  chrono::prelude::*,
  serde_json::json,
};

fn main() {
  #[cfg(feature = "easy_tokens")]
  {
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let token = paseto::tokens::PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
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

    let verified_token = paseto::tokens::validate_local_token(
      &token,
      Some("key-id:gandalf0"),
      &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
    )
    .expect("Failed to validate token!");
    println!("{:?}", verified_token);
  }
}
