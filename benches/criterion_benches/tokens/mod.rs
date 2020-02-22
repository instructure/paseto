use std::str;
use chrono::prelude::*;
use serde_json::json;
use criterion::{black_box, Criterion, Bencher};
use paseto::tokens::{
  validate_local_token,
  validate_public_token,
  PasetoPublicKey,
  builder::PasetoBuilder,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use ring::signature::KeyPair;

use crate::utils::{bench_sized_string_group};

mod builder;

fn bench_validate_local(b: &mut Bencher, s: &str) {
  let claim = s;
  let footer = s;

  let current_date_time = Utc::now();
  let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);

  let key = Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes());

  let token = PasetoBuilder::new()
    .set_encryption_key(key.clone())
    .set_issued_at(None)
    .set_expiration(dt)
    .set_issuer(String::from("issuer"))
    .set_audience(String::from("audience"))
    .set_jti(String::from("jti"))
    .set_not_before(Utc::now())
    .set_subject(String::from("test"))
    .set_claim(String::from("claim"), json!(claim))
    .set_footer(String::from(footer))
    .build()
    .expect("Can't build local v1 token");

  b.iter(|| {
    validate_local_token(
        black_box(&token),
        Some(&black_box(footer)),
        &key,
      )
      .expect("Failed to validate token!")
  });
}

fn bench_validate_public_v1(b: &mut Bencher, s: &str) {
  let claim = s;
  let footer = s;

  let current_date_time = Utc::now();
  let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);
  let private_key: &[u8] = include_bytes!("../../../src/v1/signature_rsa_example_private_key.der");
  let public_key: &[u8] = include_bytes!("../../../src/v1/signature_rsa_example_public_key.der");

  let token = PasetoBuilder::new()
    .set_rsa_key(Vec::from(private_key))
    .set_issued_at(None)
    .set_expiration(dt)
    .set_issuer(String::from("issuer"))
    .set_audience(String::from("audience"))
    .set_jti(String::from("jti"))
    .set_not_before(Utc::now())
    .set_subject(String::from("test"))
    .set_claim(String::from("claim"), json!(black_box(claim)))
    .set_footer(String::from(black_box(footer)))
    .build()
    .expect("Can't build public v1 token");

  let public_key = PasetoPublicKey::RSAPublicKey(public_key.to_vec());

  b.iter(|| {
    validate_public_token(
      black_box(&token),
      Some(&black_box(footer)),
      black_box(&public_key),
    )
    .expect("Failed to validate token!")
  });
}

fn bench_validate_public_v2(b: &mut Bencher, s: &str) {
  let claim = s;
  let footer = s;

  let current_date_time = Utc::now();
  let dt = Utc.ymd(current_date_time.year() + 1, 7, 8).and_hms(9, 10, 11);
  let sys_rand = SystemRandom::new();
  let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");

  let key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
  let token = PasetoBuilder::new()
    .set_ed25519_key(key)
    .set_issued_at(None)
    .set_expiration(dt)
    .set_issuer(String::from("issuer"))
    .set_audience(String::from("audience"))
    .set_jti(String::from("jti"))
    .set_not_before(Utc::now())
    .set_subject(String::from("test"))
    .set_claim(String::from("claim"), json!(black_box(claim)))
    .set_footer(String::from(black_box(footer)))
    .build()
    .expect("Can't build public v1 token");

  let cloned_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
  let public_key = PasetoPublicKey::ED25519PublicKey(Vec::from(cloned_key.public_key().as_ref()));

  b.iter(|| {
    validate_public_token(
      black_box(&token),
      Some(&black_box(footer)),
      black_box(&public_key),
    )
    .expect("Failed to validate token!")
  });
}

pub fn benches(c: &mut Criterion) {
  bench_sized_string_group(c, "token::validate::local", 2, &bench_validate_local);
  bench_sized_string_group(c, "token::validate::public_v1", 2, &bench_validate_public_v1);
  bench_sized_string_group(c, "token::validate::public_v2", 2, &bench_validate_public_v2);

  builder::benches(c);
}