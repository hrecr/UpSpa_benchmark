#![allow(clippy::needless_range_loop)]

// Storage-provider (server-side) micro-benchmarks.
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey};
use ed25519_dalek::Verifier;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use tspa::protocols::{sp as sp_mod, tspa as tspa_proto, upspa as upspa_proto};
use tspa::{crypto as up_crypto, crypto_tspa as tspa_crypto};

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

// UpSPA: helpers for fixture extraction

fn upspa_recover_cipherid_pt_and_sid_rsp_fk(
    fx: &upspa_proto::Fixture,
) -> ([u8; upspa_proto::CIPHERID_PT_LEN], SigningKey, [u8; 32], [u8; 32]) {
    // Deterministic r for recovery.
    let seed = seed_for(b"bench_sp/upspa/recover/v1", fx.nsp, fx.tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let r = up_crypto::random_scalar(&mut rng);
    let blinded = fx.pwd_point * r;

    let mut partials = Vec::with_capacity(fx.tsp);
    for id in 1..=fx.tsp {
        let share = fx.shares[id - 1].1;
        partials.push(blinded * share);
    }

    let state_key = up_crypto::toprf_client_eval_from_partials(
        &fx.password,
        r,
        &partials,
        &fx.lagrange_at_zero,
    );
    let pt = up_crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
        .expect("cipherid must decrypt");

    let mut sid_bytes = [0u8; 32];
    sid_bytes.copy_from_slice(&pt[0..32]);
    let sid = SigningKey::from_bytes(&sid_bytes);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&pt[32..64]);
    let mut fk = [0u8; 32];
    fk.copy_from_slice(&pt[64..96]);

    (pt, sid, rsp, fk)
}

fn build_upspa_providers(
    fx: &upspa_proto::Fixture,
    rsp: &[u8; 32],
) -> Vec<sp_mod::UpSpaProvider> {
    let mut providers = Vec::with_capacity(fx.nsp);
    for i in 1..=fx.nsp {
        let share = fx.shares[i - 1].1;
        let mut sp = sp_mod::UpSpaProvider::new(
            i as u32,
            share,
            fx.sig_pk_bytes,
            fx.cipherid.clone(),
        );
        let suid = up_crypto::hash_suid(rsp, &fx.lsj, i as u32);
        sp.put_ciphersp(suid, fx.ciphersp_per_sp[i - 1].clone());
        providers.push(sp);
    }
    providers
}

/// Build ONE pwdupd v2 payload:
/// msg = cipherid_blob || timestamp
/// sig = Ed25519 over msg (ONE signature total)
fn build_upspa_pwdupd_payload_v2(
    fx: &upspa_proto::Fixture,
    cipherid_pt: &[u8; upspa_proto::CIPHERID_PT_LEN],
    sid: &SigningKey,
) -> (Vec<u8>, Signature) {
    // Deterministic RNG for password update generation (v2).
    let seed = seed_for(b"bench_sp/upspa/pwdupd/gen/v2", fx.nsp, fx.tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);

    // Derive new_state_key using TOPRF(new_password) (client-side behavior),
    // but this is only to create a valid cid_new blob for SP verify/apply.
    let r_new = up_crypto::random_scalar(&mut rng);
    let blinded_new = fx.new_pwd_point * r_new;

    let mut partials_new = Vec::with_capacity(fx.tsp);
    for id in 1..=fx.tsp {
        let share = fx.shares[id - 1].1;
        partials_new.push(blinded_new * share);
    }

    let new_state_key = up_crypto::toprf_client_eval_from_partials(
        &fx.new_password,
        r_new,
        &partials_new,
        &fx.lagrange_at_zero,
    );

    let cid_new = up_crypto::xchacha_encrypt_detached(
        &new_state_key,
        &fx.cipherid_aad,
        cipherid_pt,
        &mut rng,
    );

    let timestamp: u64 = 0;

    // v2 msg layout: cipherid_blob || timestamp
    const MSG_LEN: usize = 24 + 96 + 16 + 8;
    let mut msg = vec![0u8; MSG_LEN];
    let mut off = 0;
    msg[off..off + 24].copy_from_slice(&cid_new.nonce);
    off += 24;
    msg[off..off + 96].copy_from_slice(&cid_new.ct);
    off += 96;
    msg[off..off + 16].copy_from_slice(&cid_new.tag);
    off += 16;
    msg[off..off + 8].copy_from_slice(&timestamp.to_le_bytes());
    off += 8;
    debug_assert_eq!(off, MSG_LEN);

    let sig = sid.sign(&msg);

    // Consume rng so the compiler can't see it as unused.
    black_box(rng.next_u64());

    (msg, sig)
}

// Bench: UpSPA server-side

fn bench_upspa_server(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "upspa";
    let fx = upspa_proto::make_fixture(nsp, tsp);
    let (cipherid_pt, sid, rsp, _fk) = upspa_recover_cipherid_pt_and_sid_rsp_fk(&fx);
    let mut providers = build_upspa_providers(&fx, &rsp);

    // Deterministic blinded point bytes for TOPRF sender eval.
    let seed = seed_for(b"bench_sp/upspa/blinded/v1", nsp, tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let r = up_crypto::random_scalar(&mut rng);
    let blinded = fx.pwd_point * r;
    let blinded_bytes = sp_mod::compress_point(&blinded);
    black_box(blinded_bytes);

    // One representative SUid for provider 1.
    let suid_1 = up_crypto::hash_suid(&rsp, &fx.lsj, 1);
    let csp_blob = fx.ciphersp_per_sp[0].clone();

    // Password update payload (ONE msg + ONE sig), reused for all providers.
    let (pwdupd_msg, pwdupd_sig) = build_upspa_pwdupd_payload_v2(&fx, &cipherid_pt, &sid);

    // ============ Primitive: TOPRF sender eval (one provider) ============
    {
        for _ in 0..warmup {
            let y = providers[0].toprf_send_eval(&blinded_bytes);
            black_box(y);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t0 = Instant::now();
            let y = providers[0].toprf_send_eval(&blinded_bytes);
            black_box(y);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "prim",
            "srv_TOPRF_send_eval_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // ============ Primitive: DB get ciphersp (one provider) ============
    {
        for _ in 0..warmup {
            let v = providers[0].get_ciphersp(&suid_1);
            black_box(v);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t0 = Instant::now();
            let v = providers[0].get_ciphersp(&suid_1);
            black_box(v);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "prim",
            "srv_DB_get_ciphersp_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // ============ Primitive: DB put ciphersp (one provider) ============
    {
        for _ in 0..warmup {
            providers[0].put_ciphersp(suid_1, csp_blob.clone());
            black_box(&providers[0]);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t0 = Instant::now();
            providers[0].put_ciphersp(suid_1, csp_blob.clone());
            black_box(&providers[0]);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "prim",
            "srv_DB_put_ciphersp_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // ============ Primitive: Ed25519 verify only (one provider) ============
    {
        let msg = &pwdupd_msg;
        let sig = &pwdupd_sig;
        for _ in 0..warmup {
            let ok = providers[0].sig_pk.verify(msg, sig).is_ok();
            black_box(ok);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t0 = Instant::now();
            let ok = providers[0].sig_pk.verify(msg, sig).is_ok();
            black_box(ok);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "prim",
            "srv_Ed25519_verify_pwdupd_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // ============ Primitive: Apply password update (verify + store) one provider ============
    {
        let msg = &pwdupd_msg;
        let sig = &pwdupd_sig;
        for _ in 0..warmup {
            let ok = providers[0].apply_password_update(msg, sig);
            black_box(ok);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t0 = Instant::now();
            let ok = providers[0].apply_password_update(msg, sig);
            black_box(ok);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "prim",
            "srv_PWDUPD_apply_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    Ok(())
}
