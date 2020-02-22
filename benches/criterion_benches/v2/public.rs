use criterion::{black_box, Criterion, Bencher};
use paseto::v2::public;
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use crate::utils::{bench_sized_string_group};

fn bench_sign(b: &mut Bencher, s: &str) {
  let msg = s;
  let footer = Some(s);
  let sys_rand = SystemRandom::new();
  let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
  let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");

  b.iter(|| {
    public::public_paseto(black_box(msg), black_box(footer), black_box(&as_key))
      .expect("Couldn't generate v2 public paseto")
  })
}

fn bench_verify(b: &mut Bencher, s: &str,) {
  let msg = s;
  let footer = Some(s);
  let sys_rand = SystemRandom::new();
  let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&sys_rand).expect("Failed to generate pkcs8 key!");
  let as_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
  let token = public::public_paseto(msg, footer, &as_key).expect("Failed to generate token");

  let cloned_key = Ed25519KeyPair::from_pkcs8(key_pkcs8.as_ref()).expect("Failed to parse keypair");
  let public_key = cloned_key.public_key().as_ref();

  b.iter(|| {
    public::verify_paseto(black_box(&token), black_box(footer), black_box(public_key))
      .expect("Couldn't verify v2 public paseto")
  })
}

pub fn benches(c: &mut Criterion) {
    bench_sized_string_group(c, "v2::public::sign", 2, &bench_sign);
    bench_sized_string_group(c, "v2::public::validate", 2, &bench_verify);
}