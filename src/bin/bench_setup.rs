use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use tspa::protocols::upspa;

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

    Stats {
        n,
        min_ns,
        p50_ns,
        p95_ns,
        max_ns,
        mean_ns,
        stddev_ns,
    }
}

fn write_header(w: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        w,
        "nsp tsp_label t_abs samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

fn seed_for_setup_point(nsp: usize, t: usize, label: u32) -> [u8; 32] {
    // deterministic per point, like your criterion version
    let seed_tag = format!("manual/upspa_setup/nsp={nsp}/t={t}/label={label}");
    let h = blake3::hash(seed_tag.as_bytes());
    *h.as_bytes()
}

// Runs the function repeatedly for approx warmup_ms, then measures exactly `samples` iterations.
fn run_setup_point<R: RngCore + CryptoRng>(
    bf: &upspa::SetupBenchFixture,
    nsp: usize,
    t: usize,
    samples: usize,
    warmup_ms: u64,
    rng: &mut R,
) -> Vec<u128> {
    // warmup for roughly warmup_ms (wall-time based, closer to your CLI semantics)
    let warmup_deadline = Instant::now() + Duration::from_millis(warmup_ms);
    while Instant::now() < warmup_deadline {
        let out = upspa::setup_user_side_bench(bf, nsp, t, rng);
        std::hint::black_box(out);
    }

    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        let out = upspa::setup_user_side_bench(bf, nsp, t, rng);
        std::hint::black_box(out);
        xs.push(t0.elapsed().as_nanos());
    }
    xs
}

fn main() -> std::io::Result<()> {
    // defaults 
    let mut nsp_list: Vec<usize> = vec![20, 40, 60, 80, 100];
    let mut tsp_abs: Option<Vec<usize>> = None;
    let mut tsp_pct: Option<Vec<u32>> = Some(vec![20, 40, 60, 80, 100]);

    let mut sample_size: usize = 100;
    let mut warmup_ms: u64 = 2000;
    let mut _measurement_ms: u64 = 5000; // kept for compatibility; not used in manual mode

    
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
            "--warmup-ms" => warmup_ms = args.next().unwrap().parse().unwrap(),
            "--measurement-ms" => _measurement_ms = args.next().unwrap().parse().unwrap(), // ignored
            "--bench" => {
                let _ = args.next();
            } // windows cargo noise
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    let file = File::create("upspa_setup.dat")?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;
    let bf = upspa::make_setup_bench_fixture();
    let mut points: Vec<(usize, usize, u32)> = Vec::new();
    for &nsp in &nsp_list {
        if let Some(ts) = &tsp_abs {
            for &t in ts {
                if (1..=nsp).contains(&t) {
                    points.push((nsp, t, t as u32));
                }
            }
        } else if let Some(pcts) = &tsp_pct {
            for &pct in pcts {
                let mut t = (nsp * pct as usize) / 100;
                if t < 1 {
                    t = 1;
                }
                if t > nsp {
                    t = nsp;
                }
                points.push((nsp, t, pct));
            }
        }
    }

    for (nsp, t, label) in points {
        let seed = seed_for_setup_point(nsp, t, label);
        let mut rng = ChaCha20Rng::from_seed(seed);

        let samples = run_setup_point(&bf, nsp, t, sample_size, warmup_ms, &mut rng);
        let st = compute_stats(samples);

        writeln!(
            &mut out,
            "{} {} {} {} {} {} {} {} {} {:.3} {:.3}",
            nsp,
            label,
            t,
            st.n,
            warmup_ms, 
            st.min_ns,
            st.p50_ns,
            st.p95_ns,
            st.max_ns,
            st.mean_ns,
            st.stddev_ns
        )?;
        out.flush()?;

        eprintln!(
            "done nsp={}, tsp_label={} (t={}) | setup p50={} ns | mean={:.1} ns",
            nsp, label, t, st.p50_ns, st.mean_ns
        );
    }

    Ok(())
}
