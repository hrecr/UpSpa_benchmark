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
    let stddev_ns = if n > 1 { (var / ((n - 1) as f64)).sqrt() } else { 0.0 };

    Stats { n, min_ns, p50_ns, p95_ns, max_ns, mean_ns, stddev_ns }
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
        let t_arrive_client = add_signed_ns(t_ready.saturating_add(resp_tx).saturating_add(prof.one_way_ns), j_resp);
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