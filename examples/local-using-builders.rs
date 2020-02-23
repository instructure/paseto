use chrono::prelude::*;
use serde_json::json;

fn main() {
  let current_date_time = Utc::now();
  let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

  let token = paseto::tokens::PasetoBuilder::new()
    .set_encryption_key(Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
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

  let verified_token = paseto::tokens::validate_local_token(
    &token,
    Some("key-id:gandalf0"),
    &"YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes(),
  )
  .expect("Failed to validate token!");
  println!("{:?}", verified_token);
}
