use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use tspa::protocols::tspa;

fn parse_list_usize(s: &str) -> Vec<usize> {
    s.split(',').filter(|x| !x.trim().is_empty()).map(|x| x.trim().parse().unwrap()).collect()
}
fn parse_list_u32(s: &str) -> Vec<u32> {
    s.split(',').filter(|x| !x.trim().is_empty()).map(|x| x.trim().parse().unwrap()).collect()
}

fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp.to_le_bytes());
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
    let stddev_ns = if n > 1 { (var / ((n - 1) as f64)).sqrt() } else { 0.0 };

    Stats { n, min_ns, p50_ns, p95_ns, max_ns, mean_ns, stddev_ns }
}

fn write_header(w: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(w, "nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns")
}

fn main() -> std::io::Result<()> {
    // defaults (same spirit as your UpSpa_benchmark CLI) :contentReference[oaicite:2]{index=2}
    let mut nsp_list: Vec<usize> = vec![20, 40, 60, 80, 100];
    let mut tsp_abs: Option<Vec<usize>> = None;
    let mut tsp_pct: Option<Vec<u32>> = Some(vec![20, 40, 60, 80, 100]);

    let mut sample_size: usize = 2000;
    let mut warmup_iters: usize = 300;
    let mut out_prefix: String = "tspa".to_string();

    // tolerant CLI (ignores cargo/libtest flags)
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--nsp" => nsp_list = parse_list_usize(&args.next().expect("missing --nsp value")),
            "--tsp" => {
                tsp_abs = Some(parse_list_usize(&args.next().expect("missing --tsp value")));
                tsp_pct = None;
            }
            "--tsp-pct" => {
                tsp_pct = Some(parse_list_u32(&args.next().expect("missing --tsp-pct value")));
                tsp_abs = None;
            }
            "--sample-size" => sample_size = args.next().unwrap().parse().unwrap(),
            "--warmup-iters" => warmup_iters = args.next().unwrap().parse().unwrap(),
            "--out-prefix" => out_prefix = args.next().unwrap(),
            "--bench" => { let _ = args.next(); } // windows cargo noise
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    let reg_file = File::create(format!("{out_prefix}_reg.dat"))?;
    let auth_file = File::create(format!("{out_prefix}_auth.dat"))?;
    let mut reg_out = BufWriter::new(reg_file);
    let mut auth_out = BufWriter::new(auth_file);

    write_header(&mut reg_out)?;
    write_header(&mut auth_out)?;

    // build points (nsp, tsp)
    let mut points: Vec<(usize, usize)> = Vec::new();
    for &nsp in &nsp_list {
        if let Some(ts) = &tsp_abs {
            for &t in ts {
                if (1..=nsp).contains(&t) {
                    points.push((nsp, t));
                }
            }
        } else if let Some(pcts) = &tsp_pct {
            for &pct in pcts {
                let mut t = (nsp * pct as usize) / 100;
                if t < 1 { t = 1; }
                if t > nsp { t = nsp; }
                points.push((nsp, t));
            }
        }
    }

    for (nsp, tsp_) in points {
        let fx = tspa::make_fixture(nsp, tsp_);

        let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"tspa/manual/reg_rng/v1", nsp, tsp_));
        let mut rng_auth = ChaCha20Rng::from_seed(seed_for(b"tspa/manual/auth_rng/v1", nsp, tsp_));

        // ---- Registration ----
        for _ in 0..warmup_iters {
            let it = tspa::make_iter_data(&fx, &mut rng_reg);
            let _ = tspa::registration_user_side(&fx, &it);
        }

        let mut reg_samples = Vec::with_capacity(sample_size);
        for _ in 0..sample_size {
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
            nsp, tsp_, reg_stats.n, warmup_iters,
            reg_stats.min_ns, reg_stats.p50_ns, reg_stats.p95_ns, reg_stats.max_ns,
            reg_stats.mean_ns, reg_stats.stddev_ns
        )?;
        reg_out.flush()?;

        // ---- Authentication ----
        for _ in 0..warmup_iters {
            let it = tspa::make_iter_data(&fx, &mut rng_auth);
            let _ = tspa::authentication_user_side(&fx, &it);
        }

        let mut auth_samples = Vec::with_capacity(sample_size);
        for _ in 0..sample_size {
            let it = tspa::make_iter_data(&fx, &mut rng_auth);
            let t0 = Instant::now();
            let out = tspa::authentication_user_side(&fx, &it);
            std::hint::black_box(out);
            auth_samples.push(t0.elapsed().as_nanos());
        }
        let auth_stats = compute_stats(auth_samples);

        writeln!(
            &mut auth_out,
            "{} {} {} {} {} {} {} {} {:.3} {:.3}",
            nsp, tsp_, auth_stats.n, warmup_iters,
            auth_stats.min_ns, auth_stats.p50_ns, auth_stats.p95_ns, auth_stats.max_ns,
            auth_stats.mean_ns, auth_stats.stddev_ns
        )?;
        auth_out.flush()?;

        eprintln!(
            "done nsp={}, tsp={} | reg p50={} ns | auth p50={} ns",
            nsp, tsp_, reg_stats.p50_ns, auth_stats.p50_ns
        );
    }

    Ok(())
}
