use std::iter;
use criterion::{black_box, Criterion, Bencher};

use crate::utils::{bench_sized_string_group};

fn bench_pae(b: &mut Bencher, s: &str, count: u64) {
    let data = iter::repeat(Vec::from(s)).take(count as usize).collect::<Vec<_>>();
    b.iter(|| {
        paseto::pae::pae(black_box(data.clone()))
    })
}

pub fn benches(c: &mut Criterion) {
    bench_sized_string_group(c, "pae/x3", 3, &| b,s | { bench_pae(b, s, 3) });
    bench_sized_string_group(c, "pae/x100", 100, &| b,s | { bench_pae(b, s, 100) });
}