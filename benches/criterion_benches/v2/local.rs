use criterion::{black_box, Criterion, Bencher};
use paseto::v2::local;
use crate::utils::{bench_sized_string_group};

fn bench_sign(b: &mut Bencher, s: &str) {
  let msg = s;
  let footer = Some(s);
  let key = "YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes();

  b.iter(|| {
    local::local_paseto(black_box(msg), black_box(footer), black_box(&key))
      .expect("Couldn't generate v2 local paseto")
  })
}

fn bench_verify(b: &mut Bencher, s: &str,) {
  let msg = s;
  let footer = Some(s);
  let key = "YELLOW SUBMARINE, BLACK WIZARDRY".as_bytes();
  let token = local::local_paseto(msg, footer, &key).expect("Failed to generate token");

  b.iter(|| {
    local::decrypt_paseto(black_box(&token), black_box(footer), black_box(key))
      .expect("Couldn't verify v2 local paseto")
  })
}

pub fn benches(c: &mut Criterion) {
    bench_sized_string_group(c, "v2::local::sign", 2, &bench_sign);
    bench_sized_string_group(c, "v2::local::validate", 2, &bench_verify);
}