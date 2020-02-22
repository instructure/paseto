use criterion::{criterion_group, criterion_main, Criterion};

mod tokens;
mod utils;
mod pae;
mod v2;

pub fn criterion_benchmark(c: &mut Criterion) {
  tokens::benches(c);
  pae::benches(c);
  v2::benches(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
