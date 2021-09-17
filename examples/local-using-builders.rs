#[cfg(feature = "easy_tokens_chrono")]
use chrono::prelude::*;
#[cfg(any(feature = "easy_tokens_chrono", feature = "easy_tokens_time"))]
use serde_json::json;
#[cfg(feature = "easy_tokens_time")]
use time::{Date, OffsetDateTime, Time};

fn main() {
  #[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
  chrono_example();

  #[cfg(all(feature = "easy_tokens_time", not(feature = "easy_tokens_chrono")))]
  time_example();

  #[cfg(all(feature = "easy_tokens_time", feature = "easy_tokens_chrono"))]
  chrono_and_time_example();
}

#[cfg(all(feature = "easy_tokens_chrono", not(feature = "easy_tokens_time")))]
fn chrono_example() {
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
    &paseto::tokens::TimeBackend::Chrono,
  )
  .expect("Failed to validate token!");
  println!("{:?}", verified_token);
}

#[cfg(all(feature = "easy_tokens_time", not(feature = "easy_tokens_chrono")))]
fn time_example() {
  let current_date_time = OffsetDateTime::now_utc();
  let dt = Date::from_calendar_date(
    current_date_time.year() + 1,
    current_date_time.month(),
    current_date_time.day(),
  )
  .unwrap()
  .with_time(Time::from_hms(09, 10, 11).expect("Failed to create time 09:10:11"))
  .assume_utc();

  let token = paseto::tokens::PasetoBuilder::new()
    .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
    .set_issued_at(None)
    .set_expiration(&dt)
    .set_issuer("instructure")
    .set_audience("wizards")
    .set_jti("gandalf0")
    .set_not_before(&OffsetDateTime::now_utc())
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
    &paseto::tokens::TimeBackend::Time,
  )
  .expect("Failed to validate token!");
  println!("{:?}", verified_token);
}

#[cfg(all(feature = "easy_tokens_time", feature = "easy_tokens_chrono"))]
fn chrono_and_time_example() {
  {
    println!("Using Time Crate:");
    let current_date_time = OffsetDateTime::now_utc();
    let dt = Date::from_calendar_date(
      current_date_time.year() + 1,
      current_date_time.month(),
      current_date_time.day(),
    )
    .unwrap()
    .with_time(Time::from_hms(09, 10, 11).expect("Failed to parse time 09:10:11"))
    .assume_utc();

    let token = paseto::tokens::PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at_time(None)
      .set_expiration_time(&dt)
      .set_issuer("instructure")
      .set_audience("wizards")
      .set_jti("gandalf0")
      .set_not_before_time(&OffsetDateTime::now_utc())
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
      &paseto::tokens::TimeBackend::Time,
    )
    .expect("Failed to validate token!");
    println!("{:?}", verified_token);
  }

  {
    println!("Using Chrono Crate");
    let current_date_time = Utc::now();
    let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

    let token = paseto::tokens::PasetoBuilder::new()
      .set_encryption_key(&Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at_chrono(None)
      .set_expiration_chrono(&dt)
      .set_issuer("instructure")
      .set_audience("wizards")
      .set_jti("gandalf0")
      .set_not_before_chrono(&Utc::now())
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
      &paseto::tokens::TimeBackend::Chrono,
    )
    .expect("Failed to validate token!");
    println!("{:?}", verified_token);
  }
}
