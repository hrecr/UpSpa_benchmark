#![allow(clippy::needless_range_loop)]
use std::fs::File;
use std::io::{BufWriter, Write};
use std::hint::black_box;

use blake3;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use tspa::protocols::sp as sp_mod;

/// Statistical summary of benchmark measurements
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

/// Computes min, max, percentiles, mean, and standard deviation from a list of measurements
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

/// Parses comma-separated values into a vector of usize
fn parse_list_usize(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse().unwrap())
        .collect()
}

/// Parses comma-separated values into a vector of u32
fn parse_list_u32(s: &str) -> Vec<u32> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse().unwrap())
        .collect()
}

/// Generates a deterministic seed from a tag and parameters for reproducible RNG
fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp.to_le_bytes());
    *h.finalize().as_bytes()
}

fn write_header(w: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        w,
        "scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

fn write_row(
    w: &mut BufWriter<File>,
    scheme: &str,
    kind: &str,
    op: &str,
    rng_in_timed: bool,
    nsp: usize,
    tsp: usize,
    warmup: usize,
    st: &Stats,
) -> std::io::Result<()> {
    writeln!(
        w,
        "{} {} {} {} {} {} {} {} {} {} {} {} {:.3} {:.3}",
        scheme,
        kind,
        op,
        if rng_in_timed { 1 } else { 0 },
        nsp,
        tsp,
        st.n,
        warmup,
        st.min_ns,
        st.p50_ns,
        st.p95_ns,
        st.max_ns,
        st.mean_ns,
        st.stddev_ns
    )
}

/// Network model

// Network configuration profile for simulating latency, jitter, and bandwidth
#[derive(Clone, Copy, Debug)]
struct NetProfile {
    name: &'static str,
    /// One-way propagation latency in ns (RTT/2).
    one_way_ns: u64,
    /// Symmetric jitter bound in ns, sampled uniformly in [-jitter,+jitter].
    jitter_ns: u64,
    /// Client access-link bandwidth in bits per second (applied to both uplink and downlink).
    bw_bps: u64,
    /// Fixed overhead bytes per message (headers, framing, etc.).
    overhead_bytes: usize,
}

// Converts milliseconds to nanoseconds
fn ms_to_ns(ms: f64) -> u64 {
    if ms <= 0.0 {
        0
    } else {
        (ms * 1_000_000.0).round() as u64
    }
}

// Converts megabits per second to bits per second
fn mbps_to_bps(mbps: f64) -> u64 {
    if mbps <= 0.0 {
        0
    } else {
        (mbps * 1_000_000.0).round() as u64
    }
}

// Calculates transmission time in nanoseconds given payload size and bandwidth
fn tx_time_ns(bytes: usize, bw_bps: u64) -> u64 {
    if bw_bps == 0 {
        return 0;
    }
    let bits = (bytes as u128) * 8u128;
    let bw = bw_bps as u128;
    // ceil(bits * 1e9 / bw)
    let ns = (bits * 1_000_000_000u128 + bw - 1) / bw;
    ns as u64
}

// Samples a random jitter value uniformly distributed in [-jitter_ns, +jitter_ns]
fn sample_jitter(rng: &mut ChaCha20Rng, jitter_ns: u64) -> i64 {
    if jitter_ns == 0 {
        return 0;
    }
    // Uniform in [-j, +j].
    let span = (jitter_ns as u128) * 2 + 1;
    let v = (rng.next_u64() as u128) % span;
    (v as i128 - jitter_ns as i128) as i64
}

// Safely adds or subtracts a signed offset to an unsigned nanosecond value
fn add_signed_ns(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub((-delta) as u64)
    }
}

// Simulates a single parallel phase where the client fans out to `k` providers.
//-------------------------------------------------------------------------------
// Model behavior:
// 1. Client queues `k` requests on shared uplink (each request transmission takes req_tx ns)
// 2. Each request travels across the network with propagation latency and jitter
// 3. Provider processes request (adds proc_ns) and sends response
// 4. Response travels back across the network with propagation latency and jitter
// 5. Client receives responses on shared downlink, queuing them in order
//-------------------------------------------------------------------------------
// Returns: Total time from first request sent to last response received
fn simulate_parallel_phase(
    k: usize,
    req_payload_bytes: usize,
    resp_payload_bytes: usize,
    proc_ns: u64,
    prof: NetProfile,
    rng: &mut ChaCha20Rng,
) -> u64 {
    if k == 0 {
        return 0;
    }

    let req_bytes = req_payload_bytes + prof.overhead_bytes;
    let resp_bytes = resp_payload_bytes + prof.overhead_bytes;

    let req_tx = tx_time_ns(req_bytes, prof.bw_bps);
    let resp_tx = tx_time_ns(resp_bytes, prof.bw_bps);
    let resp_rx = tx_time_ns(resp_bytes, prof.bw_bps);

    // Uplink queue + per-provider pipeline.
    let mut send_end = 0u64;
    let mut resp_arrivals: Vec<u64> = Vec::with_capacity(k);

    for _ in 0..k {
        send_end = send_end.saturating_add(req_tx);
        let j_req = sample_jitter(rng, prof.jitter_ns);
        let t_arrive_provider = add_signed_ns(send_end.saturating_add(prof.one_way_ns), j_req);

        let t_ready = t_arrive_provider.saturating_add(proc_ns);
        let j_resp = sample_jitter(rng, prof.jitter_ns);
        let t_arrive_client = add_signed_ns(
            t_ready
                .saturating_add(resp_tx)
                .saturating_add(prof.one_way_ns),
            j_resp,
        );
        resp_arrivals.push(t_arrive_client);
    }

    // Downlink queue.
    resp_arrivals.sort_unstable();
    let mut down_end = 0u64;
    for t in resp_arrivals {
        let start = down_end.max(t);
        down_end = start.saturating_add(resp_rx);
    }

    down_end
}

// --------------------------------------------
// v2 change: UPSPA password update simulation
// --------------------------------------------
// v2 pwdupd = TOPRF(old) + TOPRF(new) + fan-out update to all nsp providers.
#[inline]
fn simulate_upspa_pwdupd_v2(
    nsp: usize,
    tsp: usize,
    toprf_proc_ns: u64,
    pwdupd_proc_ns: u64,
    prof: NetProfile,
    rng: &mut ChaCha20Rng,
) -> u64 {
    let t_old = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        toprf_proc_ns,
        prof,
        rng,
    );

    let t_new = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        toprf_proc_ns,
        prof,
        rng,
    );

    let t_fanout = simulate_parallel_phase(
        nsp,
        sp_mod::NET_UPSPA_PWDUPD_REQ_BYTES,  // MUST be v2-sized in sp.rs
        sp_mod::NET_UPSPA_PWDUPD_RESP_BYTES,
        pwdupd_proc_ns,
        prof,
        rng,
    );

    t_old + t_new + t_fanout
}

// ------------------------------------------------------------
// One full protocol "net simulation" per scheme/op/profile
// ------------------------------------------------------------

#[inline]
fn simulate_upspa_setup(nsp: usize, _tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // One request/response (k=1) – setup is not a fan-out phase.
    simulate_parallel_phase(
        1,
        sp_mod::NET_UPSPA_SETUP_REQ_BYTES,
        sp_mod::NET_UPSPA_SETUP_RESP_BYTES,
        0,
        prof,
        rng,
    )
}

#[inline]
fn simulate_upspa_reg(nsp: usize, tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // Model: TOPRF to tsp providers + PUT ciphersp to all nsp providers
    let t_toprf = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        0,
        prof,
        rng,
    );
    let t_put = simulate_parallel_phase(
        nsp,
        sp_mod::NET_UPSPA_PUT_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_PUT_CSP_RESP_BYTES,
        0,
        prof,
        rng,
    );
    t_toprf + t_put
}

#[inline]
fn simulate_upspa_auth(_nsp: usize, tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // Model: TOPRF to tsp providers + GET ciphersp from tsp providers
    let t_toprf = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        0,
        prof,
        rng,
    );
    let t_get = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_GET_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_GET_CSP_RESP_BYTES,
        0,
        prof,
        rng,
    );
    t_toprf + t_get
}

#[inline]
fn simulate_upspa_secu(nsp: usize, tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // Model: TOPRF to tsp providers + GET ciphersp from tsp + PUT ciphersp to all nsp
    let t_toprf = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        0,
        prof,
        rng,
    );
    let t_get = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_GET_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_GET_CSP_RESP_BYTES,
        0,
        prof,
        rng,
    );
    let t_put = simulate_parallel_phase(
        nsp,
        sp_mod::NET_UPSPA_PUT_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_PUT_CSP_RESP_BYTES,
        0,
        prof,
        rng,
    );
    t_toprf + t_get + t_put
}

#[inline]
fn simulate_upspa_pwdupd(nsp: usize, tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // v2 pwdupd (ONLY CHANGE vs v1): 2x TOPRF + fan-out update to all nsp
    simulate_upspa_pwdupd_v2(nsp, tsp, 0, 0, prof, rng)
}

#[inline]
fn simulate_tspa_setup(_nsp: usize, _tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // If you had a setup message for TSPA, model it here. Keep 0 if none.
    let _ = (prof, rng);
    0
}

#[inline]
fn simulate_tspa_reg(nsp: usize, _tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // Model: registration upload to all nsp providers
    simulate_parallel_phase(
        nsp,
        sp_mod::NET_TSPA_REG_REQ_BYTES,
        sp_mod::NET_TSPA_REG_RESP_BYTES,
        0,
        prof,
        rng,
    )
}

#[inline]
fn simulate_tspa_auth(_nsp: usize, tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // Model: auth to tsp providers
    simulate_parallel_phase(
        tsp,
        sp_mod::NET_TSPA_AUTH_REQ_BYTES,
        sp_mod::NET_TSPA_AUTH_RESP_BYTES,
        0,
        prof,
        rng,
    )
}

#[inline]
fn simulate_tspa_secu(nsp: usize, _tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // If your TSPA secret update re-uploads records, model like reg.
    simulate_parallel_phase(
        nsp,
        sp_mod::NET_TSPA_REG_REQ_BYTES,
        sp_mod::NET_TSPA_REG_RESP_BYTES,
        0,
        prof,
        rng,
    )
}

#[inline]
fn simulate_tspa_pwdupd(nsp: usize, _tsp: usize, prof: NetProfile, rng: &mut ChaCha20Rng) -> u64 {
    // If your TSPA password update re-uploads records, model like reg.
    simulate_parallel_phase(
        nsp,
        sp_mod::NET_TSPA_REG_REQ_BYTES,
        sp_mod::NET_TSPA_REG_RESP_BYTES,
        0,
        prof,
        rng,
    )
}

// ------------------------------------------------------------
// CLI + main
// ------------------------------------------------------------

fn main() -> std::io::Result<()> {
    // ---- defaults ----
    let mut scheme: String = "all".to_string(); // upspa | tspa | all
    let mut nsp_list: Vec<usize> = vec![20, 40, 60, 80, 100];
    let mut tsp_abs: Option<Vec<usize>> = None;
    let mut tsp_pct: Option<Vec<u32>> = Some(vec![20, 40, 60, 80, 100]);
    let mut out_path: String = "net_bench.dat".to_string();

    let mut warmup: usize = 300;
    let mut samples: usize = 2000;
    let mut rng_in_timed: bool = false;

    // Profiles: keep simple LAN/WAN defaults (same file, same output format)
    let lan = NetProfile {
        name: "lan",
        one_way_ns: ms_to_ns(0.2) / 2, // RTT ~0.2ms
        jitter_ns: ms_to_ns(0.02),     // +-0.02ms
        bw_bps: mbps_to_bps(1000.0),   // 1 Gbps
        overhead_bytes: 0,
    };
    let wan = NetProfile {
        name: "wan",
        one_way_ns: ms_to_ns(40.0) / 2, // RTT ~40ms
        jitter_ns: ms_to_ns(2.0),       // +-2ms
        bw_bps: mbps_to_bps(100.0),     // 100 Mbps
        overhead_bytes: 0,
    };

    // ---- CLI ----
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--scheme" => scheme = args.next().expect("missing --scheme value"),
            "--nsp" => nsp_list = parse_list_usize(&args.next().expect("missing --nsp value")),
            "--tsp" => {
                tsp_abs = Some(parse_list_usize(&args.next().expect("missing --tsp value")));
                tsp_pct = None;
            }
            "--tsp-pct" => {
                tsp_pct = Some(parse_list_u32(&args.next().expect("missing --tsp-pct value")));
                tsp_abs = None;
            }
            "--out" => out_path = args.next().expect("missing --out"),
            "--samples" => samples = args.next().expect("missing --samples").parse().unwrap(),
            "--warmup" => warmup = args.next().expect("missing --warmup").parse().unwrap(),
            "--rng-in-timed" => rng_in_timed = true,
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    // ---- build points ----
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
                if t < 1 {
                    t = 1;
                }
                if t > nsp {
                    t = nsp;
                }
                points.push((nsp, t));
            }
        }
    }

    // ---- output ----
    let file = File::create(out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;

    // ---- run ----
    for (nsp, tsp) in points {
        // ---- UPSPA ----
        if scheme == "upspa" || scheme == "all" {
            // separate RNG per operation
            let mut rng_setup =
                ChaCha20Rng::from_seed(seed_for(b"net/upspa/setup_rng/v1", nsp, tsp));
            let mut rng_reg =
                ChaCha20Rng::from_seed(seed_for(b"net/upspa/reg_rng/v1", nsp, tsp));
            let mut rng_auth =
                ChaCha20Rng::from_seed(seed_for(b"net/upspa/auth_rng/v1", nsp, tsp));
            let mut rng_sec =
                ChaCha20Rng::from_seed(seed_for(b"net/upspa/sec_rng/v1", nsp, tsp));
            // v2 only for pwdupd tag:
            let mut rng_pwd =
                ChaCha20Rng::from_seed(seed_for(b"net/upspa/pwd_rng/v2", nsp, tsp));

            // LAN / WAN (same ops; "kind" encodes net profile)
            for prof in [lan, wan] {
                let kind = if prof.name == "lan" { "net_lan" } else { "net_wan" };

                // setup
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_upspa_setup(nsp, tsp, prof, &mut rng_setup) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_setup.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "upspa", kind, "setup_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // reg
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_upspa_reg(nsp, tsp, prof, &mut rng_reg) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_reg.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "upspa", kind, "reg_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // auth
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_upspa_auth(nsp, tsp, prof, &mut rng_auth) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_auth.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "upspa", kind, "auth_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // secupd
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_upspa_secu(nsp, tsp, prof, &mut rng_sec) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_sec.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "upspa", kind, "secupd_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // pwdupd (v2)
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_upspa_pwdupd(nsp, tsp, prof, &mut rng_pwd) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_pwd.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "upspa", kind, "pwdupd_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }
            }
        }

        // ---- TSPA ----
        if scheme == "tspa" || scheme == "all" {
            let mut rng_setup =
                ChaCha20Rng::from_seed(seed_for(b"net/tspa/setup_rng/v1", nsp, tsp));
            let mut rng_reg =
                ChaCha20Rng::from_seed(seed_for(b"net/tspa/reg_rng/v1", nsp, tsp));
            let mut rng_auth =
                ChaCha20Rng::from_seed(seed_for(b"net/tspa/auth_rng/v1", nsp, tsp));
            let mut rng_sec =
                ChaCha20Rng::from_seed(seed_for(b"net/tspa/sec_rng/v1", nsp, tsp));
            let mut rng_pwd =
                ChaCha20Rng::from_seed(seed_for(b"net/tspa/pwd_rng/v1", nsp, tsp));

            for prof in [lan, wan] {
                let kind = if prof.name == "lan" { "net_lan" } else { "net_wan" };

                // setup
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_tspa_setup(nsp, tsp, prof, &mut rng_setup) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_setup.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "tspa", kind, "setup_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // reg
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_tspa_reg(nsp, tsp, prof, &mut rng_reg) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_reg.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "tspa", kind, "reg_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // auth
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_tspa_auth(nsp, tsp, prof, &mut rng_auth) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_auth.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "tspa", kind, "auth_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // secupd
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_tspa_secu(nsp, tsp, prof, &mut rng_sec) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_sec.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "tspa", kind, "secupd_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }

                // pwdupd
                {
                    let mut xs: Vec<u128> = Vec::with_capacity(samples);
                    for i in 0..(warmup + samples) {
                        let t = simulate_tspa_pwdupd(nsp, tsp, prof, &mut rng_pwd) as u128;
                        let t = black_box(t);
                        if rng_in_timed {
                            black_box(rng_pwd.next_u64());
                        }
                        if i >= warmup {
                            xs.push(t);
                        }
                    }
                    let st = compute_stats(xs);
                    write_row(&mut out, "tspa", kind, "pwdupd_total", rng_in_timed, nsp, tsp, warmup, &st)?;
                }
            }
        }
    }

    out.flush()?;
    Ok(())
}
