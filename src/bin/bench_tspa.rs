// src/bin/tspa_manual_bench.rs

use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use tspa::protocols::tspa;

const WARMUP_ITERS: usize = 300;
const SAMPLES: usize = 2000;

// 5x5 grid: nsp 15..55 step 10, tsp% 20..100 step 20
const NSP_START: usize = 20;
const NSP_END: usize = 100;
const NSP_STEP: usize = 20;

const PCT_START: usize = 20;
const PCT_END: usize = 100;
const PCT_STEP: usize = 20;

fn grid_5x5() -> Vec<(usize, usize)> {
    let mut v = Vec::with_capacity(25);
    for nsp in (NSP_START..=NSP_END).step_by(NSP_STEP) {
        for pct in (PCT_START..=PCT_END).step_by(PCT_STEP) {
            let tsp_ = ((nsp * pct) / 100).max(1);
            v.push((nsp, tsp_));
        }
    }
    v
}

fn seed_for(tag: &[u8], nsp: usize, tsp_: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp_.to_le_bytes());
    let out = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(out.as_bytes());
    s
}

#[derive(Clone, Debug)]
struct Stats {
    n: usize,
    min_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    max_ns: u128,
    mean_ns: f64,
    stddev_ns: f64,
}

fn compute_stats(mut xs: Vec<u128>) -> Stats {
    xs.sort_unstable();
    let n = xs.len();
    let min_ns = xs[0];
    let max_ns = xs[n - 1];
    let p50_ns = xs[n / 2];
    let p95_ns = xs[(n * 95) / 100];

    let sum: f64 = xs.iter().map(|&x| x as f64).sum();
    let mean_ns = sum / (n as f64);

    let mut var = 0.0;
    for &x in &xs {
        let d = (x as f64) - mean_ns;
        var += d * d;
    }
    let stddev_ns = if n > 1 {
        (var / ((n - 1) as f64)).sqrt()
    } else {
        0.0
    };

    Stats { n, min_ns, p50_ns, p95_ns, max_ns, mean_ns, stddev_ns }
}

fn write_header(w: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        w,
        "nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

fn main() -> std::io::Result<()> {
    let reg_file = File::create("tspa_reg.dat")?;
    let auth_file = File::create("tspa_auth.dat")?;
    let mut reg_out = BufWriter::new(reg_file);
    let mut auth_out = BufWriter::new(auth_file);

    write_header(&mut reg_out)?;
    write_header(&mut auth_out)?;

    for (nsp, tsp_) in grid_5x5() {
        let fx = tspa::make_fixture(nsp, tsp_);

        let mut rng_reg =
            ChaCha20Rng::from_seed(seed_for(b"tspa/manual/reg_rng/v2", nsp, tsp_));
        let mut rng_auth =
            ChaCha20Rng::from_seed(seed_for(b"tspa/manual/auth_rng/v2", nsp, tsp_));

        // ---- Registration (client side) ----
        for _ in 0..WARMUP_ITERS {
            let it = tspa::make_iter_data(&fx, &mut rng_reg);
            let _ = tspa::registration_user_side(&fx, &it);
        }

        let mut reg_samples = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let it = tspa::make_iter_data(&fx, &mut rng_reg);
            let t0 = Instant::now();
            let out = tspa::registration_user_side(&fx, &it);
            std::hint::black_box(out);
            reg_samples.push(t0.elapsed().as_nanos());
        }
        let reg_stats = compute_stats(reg_samples);

        writeln!(
            &mut reg_out,
            "{} {} {} {} {} {} {} {} {:.3} {:.3}",
            nsp, tsp_, reg_stats.n, WARMUP_ITERS,
            reg_stats.min_ns, reg_stats.p50_ns, reg_stats.p95_ns, reg_stats.max_ns,
            reg_stats.mean_ns, reg_stats.stddev_ns
        )?;
        reg_out.flush()?;

        // ---- Authentication (client-side timing only: prepare + finish) ----
        for _ in 0..WARMUP_ITERS {
            let it = tspa::make_iter_data(&fx, &mut rng_auth);

            let (_uid, reqs) = tspa::auth_client_prepare(&fx, &it, &mut rng_auth);

            let mut resps = Vec::with_capacity(reqs.len());
            for (j, sp_index) in it.sp_indices.iter().enumerate() {
                resps.push(tspa::auth_sp_process(&fx, *sp_index, &reqs[j]));
            }

            let out = tspa::auth_client_finish(&fx, &reqs, &resps);
            std::hint::black_box(out);
        }

        let mut auth_samples = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let it = tspa::make_iter_data(&fx, &mut rng_auth);

            let t0 = Instant::now();
            let (_uid, reqs) = tspa::auth_client_prepare(&fx, &it, &mut rng_auth);
            let prep_ns = t0.elapsed().as_nanos();

            let mut resps = Vec::with_capacity(reqs.len());
            for (j, sp_index) in it.sp_indices.iter().enumerate() {
                resps.push(tspa::auth_sp_process(&fx, *sp_index, &reqs[j]));
            }

            let t1 = Instant::now();
            let out = tspa::auth_client_finish(&fx, &reqs, &resps);
            std::hint::black_box(out);
            let finish_ns = t1.elapsed().as_nanos();

            auth_samples.push(prep_ns + finish_ns);
        }

        let auth_stats = compute_stats(auth_samples);

        writeln!(
            &mut auth_out,
            "{} {} {} {} {} {} {} {} {:.3} {:.3}",
            nsp, tsp_, auth_stats.n, WARMUP_ITERS,
            auth_stats.min_ns, auth_stats.p50_ns, auth_stats.p95_ns, auth_stats.max_ns,
            auth_stats.mean_ns, auth_stats.stddev_ns
        )?;
        auth_out.flush()?;

        eprintln!(
            "done nsp={}, tsp={} | reg p50={} ns | auth(client) p50={} ns",
            nsp, tsp_, reg_stats.p50_ns, auth_stats.p50_ns
        );
    }

    Ok(())
}
