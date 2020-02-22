use criterion::{Criterion};

mod local;
mod public;

pub fn benches(c: &mut Criterion) {
    local::benches(c);
    public::benches(c);
}