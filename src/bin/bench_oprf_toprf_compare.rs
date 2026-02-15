use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use tspa::protocols::{tspa as tspa_proto, upspa as upspa_proto};
use tspa::{crypto_tspa as tspa_crypto, crypto as up_crypto};

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

fn parse_list_usize(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse().unwrap())
        .collect()
}
fn parse_list_u32(s: &str) -> Vec<u32> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse().unwrap())
        .collect()
}

fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp.to_le_bytes());
    *h.finalize().as_bytes()
}

fn bench_prim_p50<F: FnMut()>(warmup: usize, samples: usize, mut f: F) -> u128 {
    for _ in 0..warmup {
        f();
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        f();
        xs.push(t0.elapsed().as_nanos());
    }
    compute_stats(xs).p50_ns
}

fn main() -> std::io::Result<()> {
    // Defaults
    let mut nsp_list: Vec<usize> = vec![20, 40, 60, 80, 100];
    let mut tsp_abs: Option<Vec<usize>> = None;
    let mut tsp_pct: Option<Vec<u32>> = Some(vec![20, 40, 60, 80, 100]);

    let mut sample_size: usize = 2000;
    let mut warmup_iters: usize = 300;
    let mut out_path: String = "oprf_toprf_compare.dat".to_string();

    // CLI
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
            "--sample-size" => sample_size = args.next().expect("missing --sample-size").parse().unwrap(),
            "--warmup-iters" => warmup_iters = args.next().expect("missing --warmup-iters").parse().unwrap(),
            "--out" => out_path = args.next().expect("missing --out"),
            "--bench" => { let _ = args.next(); } // tolerate cargo/libtest noise
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    let f = File::create(out_path)?;
    let mut out = BufWriter::new(f);

    // Header (space-separated)
    writeln!(
        out,
        "nsp tsp samples warmup \
tspa_MulP_p50_ns tspa_OPRF_finalize_p50_ns tspa_OPRF_eval_full_p50_ns tspa_MulP_plus_finalize_p50_ns \
upspa_MulP_p50_ns upspa_AddP_p50_ns upspa_InvS_p50_ns upspa_OPRF_finalize_p50_ns \
upspa_TOPRF_measured_p50_ns upspa_TOPRF_pred_p50_ns toprf_measured_over_pred"
    )?;

    // Build points
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

    for (nsp, tsp) in points {
        // -------------------------
        // TSPA primitives (independent of nsp,tsp in theory, but we report per-grid anyway)
        // -------------------------
        let fx_tspa = tspa_proto::make_fixture(nsp, tsp);
        let mut rng_tspa = ChaCha20Rng::from_seed(seed_for(b"cmp/tspa/rng/v1", nsp, tsp));

        // stable scalars/points
        let k = tspa_crypto::random_scalar(&mut rng_tspa);
        let y = fx_tspa.pwd_point * k; // point used for finalize-only

        // MulP: measure only multiplication (NO compress)
        let tspa_mulp_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let p = fx_tspa.pwd_point * k;
            black_box(p);
        });

        // OPRF_finalize: hash-only finalize (includes compress inside)
        let tspa_oprf_finalize_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let outk = tspa_crypto::oprf_finalize(&fx_tspa.password, &y);
            black_box(outk);
        });

        // OPRF_eval_full: MulP + finalize (NO extra compress)
        let tspa_oprf_eval_full_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let y2 = fx_tspa.pwd_point * k;
            let outk = tspa_crypto::oprf_finalize(&fx_tspa.password, &y2);
            black_box(outk);
        });

        let tspa_mulp_plus_finalize_p50 =
            (tspa_mulp_p50 as u128) + (tspa_oprf_finalize_p50 as u128);

        // -------------------------
        // UPSPA primitives + measured TOPRF
        // -------------------------
        let fx_up = upspa_proto::make_fixture(nsp, tsp);
        let mut rng_up = ChaCha20Rng::from_seed(seed_for(b"cmp/upspa/rng/v1", nsp, tsp));

        // pick stable scalars/points for primitives
        let s1 = up_crypto::random_scalar(&mut rng_up);
        let s2 = up_crypto::random_scalar(&mut rng_up);
        let p1: RistrettoPoint = fx_up.pwd_point * s1;
        let p2: RistrettoPoint = fx_up.pwd_point * s2;

        // MulP (no compress)
        let up_mulp_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let p = fx_up.pwd_point * s1;
            black_box(p);
        });

        // AddP: point addition only
        let up_addp_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let s = p1 + p2;
            black_box(s);
        });

        // InvS: scalar inversion
        let up_invs_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let inv = s1.invert();
            black_box(inv);
        });

        // OPRF_finalize (UPSPA): compress+hash
        let up_oprf_finalize_p50 = bench_prim_p50(warmup_iters, sample_size, || {
            let y3 = fx_up.pwd_point * s1;
            let outk = up_crypto::oprf_finalize(&fx_up.password, &y3);
            black_box(outk);
        });

        // TOPRF measured (matches your bench_all style: include blinding MulP in caller)
        let mut rng_toprf = ChaCha20Rng::from_seed(seed_for(b"cmp/upspa/toprf_rng/v1", nsp, tsp));

        // warmup
        for _ in 0..warmup_iters {
            let it = upspa_proto::make_iter_data(&fx_up, &mut rng_toprf); // server-side partial prep
            let b = &fx_up.pwd_point * it.r;
            black_box(b);
            let k_out = up_crypto::toprf_client_eval_from_partials(
                &fx_up.password,
                it.r,
                &it.partials,
                &fx_up.lagrange_at_zero,
            );
            black_box(k_out);
        }

        let mut xs = Vec::with_capacity(sample_size);
        for _ in 0..sample_size {
            let it = upspa_proto::make_iter_data(&fx_up, &mut rng_toprf); // outside timing
            let t0 = Instant::now();
            let b = &fx_up.pwd_point * it.r;
            black_box(b);
            let k_out = up_crypto::toprf_client_eval_from_partials(
                &fx_up.password,
                it.r,
                &it.partials,
                &fx_up.lagrange_at_zero,
            );
            black_box(k_out);
            xs.push(t0.elapsed().as_nanos());
        }
        let up_toprf_measured_p50 = compute_stats(xs).p50_ns;

        // TOPRF predicted from primitives:
        // (t+2)*MulP + t*AddP + InvS + OPRF_finalize
        let t_u128 = tsp as u128;
        let up_toprf_pred_p50 =
            (t_u128 + 2) * (up_mulp_p50 as u128)
            + (t_u128) * (up_addp_p50 as u128)
            + (up_invs_p50 as u128)
            + (up_oprf_finalize_p50 as u128);

        let ratio = (up_toprf_measured_p50 as f64) / (up_toprf_pred_p50 as f64);

        writeln!(
            out,
            "{} {} {} {} \
{} {} {} {} \
{} {} {} {} \
{} {} {:.6}",
            nsp,
            tsp,
            sample_size,
            warmup_iters,
            tspa_mulp_p50,
            tspa_oprf_finalize_p50,
            tspa_oprf_eval_full_p50,
            tspa_mulp_plus_finalize_p50,
            up_mulp_p50,
            up_addp_p50,
            up_invs_p50,
            up_oprf_finalize_p50,
            up_toprf_measured_p50,
            up_toprf_pred_p50,
            ratio
        )?;

        out.flush()?;
        eprintln!("done nsp={nsp} tsp={tsp}");
    }

    Ok(())
}
