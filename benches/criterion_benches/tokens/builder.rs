use std::str;
use chrono::prelude::*;
use serde_json::json;
use criterion::{black_box, Criterion, Bencher};
use paseto::tokens::builder::PasetoBuilder;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

use crate::utils::{bench_sized_string_group};

fn bench_construct_local(b: &mut Bencher, s: &str) {
  let claim = s;
  let footer = s;
  b.iter(|| {
    PasetoBuilder::new()
      .set_encryption_key(Vec::from("YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes()))
      .set_issued_at(None)
      .set_expiration(Utc::now())
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(black_box(claim)))
      .set_footer(String::from(black_box(footer)))
      .build()
      .expect("Can't build local v1 token")
  });
}

fn bench_construct_public_v1(b: &mut Bencher, s: &str) {
  let claim = s;
  let footer = s;

  let private_key: &[u8] = include_bytes!("../../../src/v1/signature_rsa_example_private_key.der");

  b.iter(|| {
    PasetoBuilder::new()
      .set_rsa_key(Vec::from(black_box(private_key)))
      .set_issued_at(None)
      .set_expiration(Utc::now())
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(black_box(claim)))
      .set_footer(String::from(black_box(footer)))
      .build()
      .expect("Can't build public v1 token")
  });
}

fn bench_construct_public_v2(b: &mut Bencher, s: &str) {
  let claim = s;
  let footer = s;

  let sys_rand = SystemRandom::new();
  let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");

  b.iter(|| {
    let key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
    PasetoBuilder::new()
      .set_ed25519_key(key)
      .set_issued_at(None)
      .set_expiration(Utc::now())
      .set_issuer(String::from("issuer"))
      .set_audience(String::from("audience"))
      .set_jti(String::from("jti"))
      .set_not_before(Utc::now())
      .set_subject(String::from("test"))
      .set_claim(String::from("claim"), json!(black_box(claim)))
      .set_footer(String::from(black_box(footer)))
      .build()
      .expect("Can't build public v1 token")
  });
}

pub fn benches(c: &mut Criterion) {
  bench_sized_string_group(c, "token::builder::local", 2, &bench_construct_local);
  bench_sized_string_group(c, "token::builder::public_v1", 2, &bench_construct_public_v1);
  bench_sized_string_group(c, "token::builder::public_v2", 2, &bench_construct_public_v2);
}