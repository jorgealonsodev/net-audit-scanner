// Benchmark placeholders — criterion harness ready.
// Actual benchmarks will be added when performance-critical code exists.

use criterion::{Criterion, criterion_group, criterion_main};

fn placeholder_benchmark(_c: &mut Criterion) {
    // TODO: Add real benchmarks when scanner/cve modules are implemented.
}

criterion_group!(benches, placeholder_benchmark);
criterion_main!(benches);
