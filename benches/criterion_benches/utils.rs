use std::iter;
use std::str;
use criterion::{Criterion, Bencher, Throughput, BenchmarkId};

static KB: usize = 1024;
static BENCH_SIZES: [usize; 4] = [1, 1 * KB, 4 * KB, 16 * KB];

/// Run multiple benchmarks with strings of growing size relevant for paseto usage
pub fn bench_sized_string_group(c: &mut Criterion, name: &str, factor: u64, f: &dyn Fn(&mut Bencher, &str)) {
    let mut group = c.benchmark_group(name);
    for size in BENCH_SIZES.iter() {
        group.throughput(Throughput::Bytes((*size as u64) * factor));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
          let bytes = iter::repeat(20u8).take(size).collect::<Vec<_>>();
          let s = str::from_utf8(&bytes).unwrap();

          f(b, s);
        });
    }
    group.finish();
  }