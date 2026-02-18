#![allow(clippy::needless_range_loop)]

use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey};

use tspa::protocols::{tspa as tspa_proto, upspa as upspa_proto};
use tspa::{crypto as up_crypto, crypto_tspa as tspa_crypto};

// AEAD encryption (fixed-nonce variant to avoid RNG in critical path)
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};

/// Statistics structure to store timing measurements in nanoseconds
/// Used to record benchmark results for each operation
#[derive(Clone, Debug)]
struct Stats {
    n: usize,       // Number of samples
    min_ns: u128,   // Minimum execution time in nanoseconds
    p50_ns: u128,   // 50th percentile (median) in nanoseconds
    p95_ns: u128,   // 95th percentile in nanoseconds
    max_ns: u128,   // Maximum execution time in nanoseconds
    mean_ns: f64,   // Mean execution time in nanoseconds
    stddev_ns: f64, // Standard deviation in nanoseconds
}

/// Computes statistical measures from a vector of timing samples (in nanoseconds)
/// Returns min, median, p95, max, mean, and standard deviation
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

/// Parse comma-separated string into a vector of usize values
fn parse_list_usize(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse().unwrap())
        .collect()
}

/// Parse comma-separated string into a vector of u32 values
fn parse_list_u32(s: &str) -> Vec<u32> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse().unwrap())
        .collect()
}

/// Generate a deterministic 32-byte seed from a tag and parameters
/// Used to create RNG seeds for reproducible benchmarks
fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Write CSV header to output file
fn write_header(w: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        w,
        "scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

/// Write a single benchmark result row to CSV output
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

/// Encrypt plaintext using XChaCha20-Poly1305 with a fixed nonce
/// This avoids RNG in the timed region, allowing pure crypto performance measurement
/// Output layout matches up_crypto::CtBlob structure
fn upspa_aead_encrypt_fixed<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8; PT_LEN],
    nonce: [u8; up_crypto::NONCE_LEN],
) -> up_crypto::CtBlob<PT_LEN> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let xnonce = XNonce::from_slice(&nonce);

    let mut ct = *plaintext;
    let tag = cipher.encrypt_in_place_detached(xnonce, aad, &mut ct).unwrap();

    let mut tag_bytes = [0u8; up_crypto::TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());

    up_crypto::CtBlob { nonce, ct, tag: tag_bytes }
}

/// Recover state key and decrypt cipherid plaintext
/// This includes TOPRF evaluation and AEAD decryption (cipherid)
fn upspa_recover_state_and_cipherid_pt(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
) -> ([u8; 32], [u8; upspa_proto::CIPHERID_PT_LEN]) {
    // Include "blind mul" parity
    let b = &fx.pwd_point * it.r;
    black_box(b);

    // Evaluate TOPRF from server partials to get state key
    let state_key = up_crypto::toprf_client_eval_from_partials(
        &fx.password,
        it.r,
        &it.partials,
        &fx.lagrange_at_zero,
    );

    let pt = up_crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
        .expect("cipherid must decrypt");

    (state_key, pt)
}

/// Extract three values from decrypted cipherid plaintext:
/// - sid: Signing key (first 32 bytes)
/// - rsp: Random string (next 32 bytes)
/// - fk: Fairness key (next 32 bytes)
fn upspa_extract_rsp_fk_sid(
    cipherid_pt: &[u8; upspa_proto::CIPHERID_PT_LEN],
) -> ([u8; 32], [u8; 32], SigningKey) {
    let mut sid_bytes = [0u8; 32];
    sid_bytes.copy_from_slice(&cipherid_pt[0..32]);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&cipherid_pt[32..64]);

    let mut fk = [0u8; 32];
    fk.copy_from_slice(&cipherid_pt[64..96]);

    let sid = SigningKey::from_bytes(&sid_bytes);
    (rsp, fk, sid)
}

/// Precompute RNG outputs for registration OUTSIDE the timed region
fn upspa_precompute_reg_rng_outputs(r: Scalar) -> ([u8; 32], [u8; up_crypto::NONCE_LEN]) {
    let mut seed = r.to_bytes();
    seed[0] ^= 0xA5;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut rlsj = [0u8; 32];
    rng.fill_bytes(&mut rlsj);

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    (rlsj, nonce)
}

/// Precompute RNG outputs for secret update OUTSIDE the timed region
fn upspa_precompute_secu_rng_outputs(r: Scalar) -> ([u8; 32], [u8; up_crypto::NONCE_LEN]) {
    let mut seed = r.to_bytes();
    seed[0] ^= 0x3C;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut new_rlsj = [0u8; 32];
    rng.fill_bytes(&mut new_rlsj);

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    (new_rlsj, nonce)
}

/// Precompute password update RNG outputs OUTSIDE the timed region
fn upspa_precompute_pwdupd_nonce(r: Scalar) -> [u8; up_crypto::NONCE_LEN] {
    let mut seed = r.to_bytes();
    seed[0] ^= 0x77;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Perform UPSPA registration with RNG precomputed outside timed region
fn upspa_registration_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    rlsj: [u8; 32],
    enc_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/registration/acc/v1");

    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    let ctr: u64 = 0;
    let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
    pt[0..32].copy_from_slice(&rlsj);
    pt[32..40].copy_from_slice(&ctr.to_le_bytes());
    let cj = upspa_aead_encrypt_fixed(&fk, &fx.ciphersp_aad, &pt, enc_nonce);

    let vinfo = up_crypto::hash_vinfo(&rlsj, &fx.lsj);
    acc.update(vinfo.as_ref());
    acc.update(&cj.nonce);
    acc.update(&cj.ct);
    acc.update(&cj.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// Perform UPSPA secret update with RNG precomputed outside timed region
fn upspa_secu_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    new_rlsj: [u8; 32],
    enc_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/secret_update/acc/v3");

    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // NOTE: your current secret-update decrypts tsp ciphersp blobs (ids_for_t),
    // which is fine since you didn't ask to change secret-update fairness.
    let mut old_ctr: u64 = 0;
    let mut old_rlsj = [0u8; 32];
    for &id in fx.ids_for_t.iter() {
        let blob = &fx.ciphersp_per_sp[(id - 1) as usize];
        let pt = up_crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob).unwrap();

        let mut rlsj = [0u8; 32];
        rlsj.copy_from_slice(&pt[0..32]);

        let mut ctr_bytes = [0u8; 8];
        ctr_bytes.copy_from_slice(&pt[32..40]);
        let ctr = u64::from_le_bytes(ctr_bytes);

        if ctr >= old_ctr {
            old_ctr = ctr;
            old_rlsj = rlsj;
        }
    }

    let vinfo_prime = up_crypto::hash_vinfo(&old_rlsj, &fx.lsj);
    let new_ctr = old_ctr.wrapping_add(1);

    let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
    pt[0..32].copy_from_slice(&new_rlsj);
    pt[32..40].copy_from_slice(&new_ctr.to_le_bytes());
    let newciphersp = upspa_aead_encrypt_fixed(&fk, &fx.ciphersp_aad, &pt, enc_nonce);

    let newvinfo = up_crypto::hash_vinfo(&new_rlsj, &fx.lsj);

    acc.update(&old_ctr.to_le_bytes());
    acc.update(vinfo_prime.as_ref());
    acc.update(&new_ctr.to_le_bytes());
    acc.update(newvinfo.as_ref());
    acc.update(&newciphersp.nonce);
    acc.update(&newciphersp.ct);
    acc.update(&newciphersp.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// Perform UPSPA password update with RNG precomputed outside timed region
fn upspa_pwdupd_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    newcipherid_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    // First TOPRF round + decrypt of current cipherid.
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (_rsp, _fk, sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    // Second TOPRF round (NEW password) — server partials are precomputed in IterData.
    let b_new = &fx.new_pwd_point * it.r_new;
    black_box(b_new);

    let new_state_key = up_crypto::toprf_client_eval_from_partials(
        &fx.new_password,
        it.r_new,
        &it.partials_new,
        &fx.lagrange_at_zero,
    );

    // Re-encrypt the SAME plaintext under the new password-derived key.
    let cid_new =
        upspa_aead_encrypt_fixed(&new_state_key, &fx.cipherid_aad, &cipherid_pt, newcipherid_nonce);

    // One signature (no per-provider index).
    let timestamp: u64 = 0;
    const MSG_LEN: usize = 24 + 96 + 16 + 8; // nonce || ct || tag || time
    let mut msg = [0u8; MSG_LEN];
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
    let sig_bytes = sig.to_bytes();

    // Benchmark-only accumulator.
    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/password_update/acc/v2");
    acc.update(&sig_bytes);
    acc.update(&cid_new.nonce);
    acc.update(&cid_new.ct);
    acc.update(&cid_new.tag);
    acc.update(&timestamp.to_le_bytes());

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

//
/
// UPDATED UPSPA AUTH FOR YOUR REQUEST: EXACTLY 2 DECRYPTIONS
//   - 1 decrypt cipherid (inside upspa_recover_state_and_cipherid_pt)
//   - 1 decrypt ciphersp (only one provider)
// 
//
fn upspa_auth_two_decryptions(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
) -> [u8; 32] {
    // decrypt #1: cipherid (also does TOPRF eval)
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/authentication/acc/2dec_v1");

    // SUid hashes for tsp contacted providers (ids_for_t)
    for &id in fx.ids_for_t.iter() {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, id);
        acc.update(suid.as_ref());
    }

    // decrypt #2: exactly ONE ciphersp (pick first contacted provider)
    let id0 = fx.ids_for_t[0];
    let blob = &fx.ciphersp_per_sp[(id0 - 1) as usize];
    let pt = up_crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob)
        .expect("ciphersp must decrypt");

    let mut rlsj = [0u8; 32];
    rlsj.copy_from_slice(&pt[0..32]);

    let mut ctr_bytes = [0u8; 8];
    ctr_bytes.copy_from_slice(&pt[32..40]);
    let ctr = u64::from_le_bytes(ctr_bytes);

    let vinfo = up_crypto::hash_vinfo(&rlsj, &fx.lsj);
    acc.update(&ctr.to_le_bytes());
    acc.update(vinfo.as_ref());

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// Benchmark UPSPA protocol operations
fn bench_upspa(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "upspa";
    let fx = upspa_proto::make_fixture(nsp, tsp);

    let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/reg_rng/v1", nsp, tsp));
    let mut rng_auth = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/auth_rng/v1", nsp, tsp));
    let mut rng_sec = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/sec_rng/v1", nsp, tsp));
    let mut rng_pwd = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/pwd_rng/v1", nsp, tsp));

    // Registration
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_reg);
            let _ = if rng_in_timed {
                upspa_proto::registration_user_side(&fx, &it)
            } else {
                let (rlsj, nonce) = upspa_precompute_reg_rng_outputs(it.r);
                upspa_registration_no_rng(&fx, &it, rlsj, nonce)
            };
        }

        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_reg);

            let (rlsj, nonce) = if rng_in_timed {
                ([0u8; 32], [0u8; up_crypto::NONCE_LEN])
            } else {
                upspa_precompute_reg_rng_outputs(it.r)
            };

            let t0 = Instant::now();
            let outv = if rng_in_timed {
                upspa_proto::registration_user_side(&fx, &it)
            } else {
                upspa_registration_no_rng(&fx, &it, rlsj, nonce)
            };
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "proto",
            "reg",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // Authentication (2 decryptions: cipherid + ciphersp)
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
            let _ = upspa_auth_two_decryptions(&fx, &it);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
            let t0 = Instant::now();
            let outv = upspa_auth_two_decryptions(&fx, &it);
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "proto",
            "auth",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // Secret update
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_sec);
            let _ = if rng_in_timed {
                upspa_proto::secret_update_user_side(&fx, &it)
            } else {
                let (new_rlsj, nonce) = upspa_precompute_secu_rng_outputs(it.r);
                upspa_secu_no_rng(&fx, &it, new_rlsj, nonce)
            };
        }

        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_sec);

            let (new_rlsj, nonce) = if rng_in_timed {
                ([0u8; 32], [0u8; up_crypto::NONCE_LEN])
            } else {
                upspa_precompute_secu_rng_outputs(it.r)
            };

            let t0 = Instant::now();
            let outv = if rng_in_timed {
                upspa_proto::secret_update_user_side(&fx, &it)
            } else {
                upspa_secu_no_rng(&fx, &it, new_rlsj, nonce)
            };
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "proto",
            "secupd",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // Password update
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_pwd);
            let _ = if rng_in_timed {
                upspa_proto::password_update_user_side(&fx, &it)
            } else {
                let nonce = upspa_precompute_pwdupd_nonce(it.r);
                upspa_pwdupd_no_rng(&fx, &it, nonce)
            };
        }

        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_pwd);

            let nonce = if rng_in_timed {
                [0u8; up_crypto::NONCE_LEN]
            } else {
                upspa_precompute_pwdupd_nonce(it.r)
            };

            let t0 = Instant::now();
            let outv = if rng_in_timed {
                upspa_proto::password_update_user_side(&fx, &it)
            } else {
                upspa_pwdupd_no_rng(&fx, &it, nonce)
            };
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(
            out,
            scheme,
            "proto",
            "pwdupd",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }



    // CRYPTOGRAPHIC PRIMITIVES
    {
        let mut rng0 = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/prim/derive/v1", nsp, tsp));
        let it0 = upspa_proto::make_iter_data(&fx, &mut rng0);
        let (state_key0, cipherid_pt0) = upspa_recover_state_and_cipherid_pt(&fx, &it0);
        let (rsp0, fk0, _sid0) = upspa_extract_rsp_fk_sid(&cipherid_pt0);

        // TOPRF receiver-side evaluation
        {
            let mut rng = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/prim/toprf/v1", nsp, tsp));
            for _ in 0..warmup {
                let it = upspa_proto::make_iter_data(&fx, &mut rng);
                let b = &fx.pwd_point * it.r;
                black_box(b);
                let k = up_crypto::toprf_client_eval_from_partials(
                    &fx.password,
                    it.r,
                    &it.partials,
                    &fx.lagrange_at_zero,
                );
                black_box(k);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let it = upspa_proto::make_iter_data(&fx, &mut rng);
                let t0 = Instant::now();
                let b = &fx.pwd_point * it.r;
                black_box(b);
                let k = up_crypto::toprf_client_eval_from_partials(
                    &fx.password,
                    it.r,
                    &it.partials,
                    &fx.lagrange_at_zero,
                );
                black_box(k);
                xs.push(t0.elapsed().as_nanos());
            }
            // UPDATED LABEL (not vague)
            write_row(
                out,
                scheme,
                "prim",
                "TOPRF_recv_eval_tsp",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // AEAD decrypt cipherid
        {
            for _ in 0..warmup {
                let pt =
                    up_crypto::xchacha_decrypt_detached(&state_key0, &fx.cipherid_aad, &fx.cipherid)
                        .unwrap();
                black_box(pt);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let pt =
                    up_crypto::xchacha_decrypt_detached(&state_key0, &fx.cipherid_aad, &fx.cipherid)
                        .unwrap();
                black_box(pt);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "AEAD_DEC_cipherid",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // AEAD decrypt ciphersp
        {
            let one = &fx.ciphersp_per_sp[0];
            for _ in 0..warmup {
                let pt = up_crypto::xchacha_decrypt_detached(&fk0, &fx.ciphersp_aad, one).unwrap();
                black_box(pt);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let pt = up_crypto::xchacha_decrypt_detached(&fk0, &fx.ciphersp_aad, one).unwrap();
                black_box(pt);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "AEAD_DEC_ciphersp",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // AEAD encrypt ciphersp
        {
            let ctr: u64 = 0;
            let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
            pt[0..32].copy_from_slice(&fx.cached_rlsj);
            pt[32..40].copy_from_slice(&ctr.to_le_bytes());

            if rng_in_timed {
                let mut rng =
                    ChaCha20Rng::from_seed(seed_for(b"unified/upspa/prim/aead_enc_rng/v1", nsp, tsp));
                for _ in 0..warmup {
                    let c = up_crypto::xchacha_encrypt_detached(&fk0, &fx.ciphersp_aad, &pt, &mut rng);
                    black_box(c.ct);
                    black_box(c.tag);
                }
                let mut xs = Vec::with_capacity(samples);
                for _ in 0..samples {
                    let t0 = Instant::now();
                    let c = up_crypto::xchacha_encrypt_detached(&fk0, &fx.ciphersp_aad, &pt, &mut rng);
                    black_box(c.ct);
                    black_box(c.tag);
                    xs.push(t0.elapsed().as_nanos());
                }
                write_row(
                    out,
                    scheme,
                    "prim",
                    "AEAD_ENC_ciphersp_with_rng",
                    rng_in_timed,
                    nsp,
                    tsp,
                    warmup,
                    &compute_stats(xs),
                )?;
            } else {
                let nonce = [0x42u8; up_crypto::NONCE_LEN];
                for _ in 0..warmup {
                    let c = upspa_aead_encrypt_fixed(&fk0, &fx.ciphersp_aad, &pt, nonce);
                    black_box(c.ct);
                    black_box(c.tag);
                }
                let mut xs = Vec::with_capacity(samples);
                for _ in 0..samples {
                    let t0 = Instant::now();
                    let c = upspa_aead_encrypt_fixed(&fk0, &fx.ciphersp_aad, &pt, nonce);
                    black_box(c.ct);
                    black_box(c.tag);
                    xs.push(t0.elapsed().as_nanos());
                }
                write_row(
                    out,
                    scheme,
                    "prim",
                    "AEAD_ENC_ciphersp_fixed_nonce",
                    rng_in_timed,
                    nsp,
                    tsp,
                    warmup,
                    &compute_stats(xs),
                )?;
            }
        }

        // Hash suid
        {
            for _ in 0..warmup {
                let h = up_crypto::hash_suid(&rsp0, &fx.lsj, 1);
                black_box(h);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let h = up_crypto::hash_suid(&rsp0, &fx.lsj, 1);
                black_box(h);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "HASH_suid",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // Hash vinfo
        {
            for _ in 0..warmup {
                let h = up_crypto::hash_vinfo(&fx.cached_rlsj, &fx.lsj);
                black_box(h);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let h = up_crypto::hash_vinfo(&fx.cached_rlsj, &fx.lsj);
                black_box(h);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "HASH_vinfo",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }
    }

    Ok(())
}

/// Benchmark TSPA protocol operations
fn bench_tspa(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "tspa";
    let fx = tspa_proto::make_fixture(nsp, tsp);

    let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"unified/tspa/reg_rng/v1", nsp, tsp));
    let mut rng_auth = ChaCha20Rng::from_seed(seed_for(b"unified/tspa/auth_rng/v1", nsp, tsp));

    // Registration
    {
        for _ in 0..warmup {
            if rng_in_timed {
                let t0 = Instant::now();
                let it = tspa_proto::make_iter_data(&fx, &mut rng_reg);
                let outv = tspa_proto::registration_user_side(&fx, &it);
                black_box(outv);
                black_box(t0.elapsed().as_nanos());
            } else {
                let it = tspa_proto::make_iter_data(&fx, &mut rng_reg);
                let _ = tspa_proto::registration_user_side(&fx, &it);
            }
        }

        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            if rng_in_timed {
                let t0 = Instant::now();
                let it = tspa_proto::make_iter_data(&fx, &mut rng_reg);
                let outv = tspa_proto::registration_user_side(&fx, &it);
                black_box(outv);
                xs.push(t0.elapsed().as_nanos());
            } else {
                let it = tspa_proto::make_iter_data(&fx, &mut rng_reg);
                let t0 = Instant::now();
                let outv = tspa_proto::registration_user_side(&fx, &it);
                black_box(outv);
                xs.push(t0.elapsed().as_nanos());
            }
        }
        write_row(
            out,
            scheme,
            "proto",
            "reg",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }

    // Authentication
    {
        for _ in 0..warmup {
            if rng_in_timed {
                let t0 = Instant::now();
                let it = tspa_proto::make_iter_data(&fx, &mut rng_auth);
                let outv = tspa_proto::authentication_user_side(&fx, &it);
                black_box(outv);
                black_box(t0.elapsed().as_nanos());
            } else {
                let it = tspa_proto::make_iter_data(&fx, &mut rng_auth);
                let _ = tspa_proto::authentication_user_side(&fx, &it);
            }
        }

        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            if rng_in_timed {
                let t0 = Instant::now();
                let it = tspa_proto::make_iter_data(&fx, &mut rng_auth);
                let outv = tspa_proto::authentication_user_side(&fx, &it);
                black_box(outv);
                xs.push(t0.elapsed().as_nanos());
            } else {
                let it = tspa_proto::make_iter_data(&fx, &mut rng_auth);
                let t0 = Instant::now();
                let outv = tspa_proto::authentication_user_side(&fx, &it);
                black_box(outv);
                xs.push(t0.elapsed().as_nanos());
            }
        }

        write_row(
            out,
            scheme,
            "proto",
            "auth",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &compute_stats(xs),
        )?;
    }


    // CRYPTOGRAPHIC PRIMITIVES
  
    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"unified/tspa/prim/rng/v1", nsp, tsp));

        let k = tspa_crypto::random_scalar(&mut rng);
        let y = fx.pwd_point * k;

        let rnd32 = tspa_crypto::rand_bytes::<32>(&mut rng);
        let key = tspa_crypto::oprf_finalize(&fx.password, &y);
        let iv = tspa_crypto::rand_bytes::<16>(&mut rng);
        let block = tspa_crypto::rand_bytes::<32>(&mut rng);

        let a = tspa_crypto::random_scalar(&mut rng);
        let b = tspa_crypto::random_scalar(&mut rng);
        let c = tspa_crypto::random_scalar(&mut rng);

        // Hash storuid
        {
            for _ in 0..warmup {
                let h = tspa_crypto::hash_storuid(&fx.uid, &fx.lsj);
                black_box(h);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let h = tspa_crypto::hash_storuid(&fx.uid, &fx.lsj);
                black_box(h);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "HASH_storuid",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // Hash vinfo
        {
            for _ in 0..warmup {
                let h = tspa_crypto::hash_vinfo(&rnd32, &fx.lsj);
                black_box(h);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let h = tspa_crypto::hash_vinfo(&rnd32, &fx.lsj);
                black_box(h);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "HASH_vinfo",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // OPRF finalize
        {
            for _ in 0..warmup {
                let outk = tspa_crypto::oprf_finalize(&fx.password, &y);
                black_box(outk);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let outk = tspa_crypto::oprf_finalize(&fx.password, &y);
                black_box(outk);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "OPRF_finalize",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // OPRF evaluation (MulP + finalize)
        {
            for _ in 0..warmup {
                let y2 = fx.pwd_point * k;
                let outk = tspa_crypto::oprf_finalize(&fx.password, &y2);
                black_box(outk);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let y2 = fx.pwd_point * k;
                let outk = tspa_crypto::oprf_finalize(&fx.password, &y2);
                black_box(outk);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "OPRF_eval_full",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // OPRF receiver-side evaluation for tsp providers
        {
            let mut rng2 =
                ChaCha20Rng::from_seed(seed_for(b"unified/tspa/prim/oprf_recv_tsp/v1", nsp, tsp));

            for _ in 0..warmup {
                let r = tspa_crypto::random_scalar(&mut rng2);

                // server replies OUTSIDE timing (simulation)
                let blinded = fx.pwd_point * r;
                let mut z_sel = Vec::with_capacity(fx.tsp);
                for j in 0..fx.tsp {
                    z_sel.push(blinded * fx.auth_oprf_keys_sel[j]);
                }

                // client work
                let bpt = fx.pwd_point * r;
                black_box(bpt);

                let r_inv = r.invert();
                for j in 0..fx.tsp {
                    let yj = z_sel[j] * r_inv;
                    let kout = tspa_crypto::oprf_finalize(&fx.password, &yj);
                    black_box(kout);
                }
            }

            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let r = tspa_crypto::random_scalar(&mut rng2);

                // server replies OUTSIDE timing (simulation)
                let blinded = fx.pwd_point * r;
                let mut z_sel = Vec::with_capacity(fx.tsp);
                for j in 0..fx.tsp {
                    z_sel.push(blinded * fx.auth_oprf_keys_sel[j]);
                }

                let t0 = Instant::now();

                // client work
                let bpt = fx.pwd_point * r;
                black_box(bpt);

                let r_inv = r.invert();
                for j in 0..fx.tsp {
                    let yj = z_sel[j] * r_inv;
                    let kout = tspa_crypto::oprf_finalize(&fx.password, &yj);
                    black_box(kout);
                }

                xs.push(t0.elapsed().as_nanos());
            }

            write_row(
                out,
                scheme,
                "prim",
                "OPRF_recv_eval_tsp",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // MulP (point-scalar multiplication)
        {
            for _ in 0..warmup {
                let p = fx.pwd_point * k;
                black_box(p);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let p = fx.pwd_point * k;
                black_box(p);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "MulP_point_scalar",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // InvS (scalar inversion)
        {
            for _ in 0..warmup {
                let inv = k.invert();
                black_box(inv);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let inv = k.invert();
                black_box(inv);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "InvS_scalar_invert",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // Field operation (mul+add)
        {
            for _ in 0..warmup {
                let r = a * b + c;
                black_box(r);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let r = a * b + c;
                black_box(r);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "FieldOp_mul_add",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // AES-CTR XOR 32 bytes
        {
            for _ in 0..warmup {
                let ct = tspa_crypto::aes256ctr_xor_32(key, iv, block);
                black_box(ct);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let ct = tspa_crypto::aes256ctr_xor_32(key, iv, block);
                black_box(ct);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "AES256CTR_xor_32",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }

        // Polynomial evaluation (degree t-1)
        {
            let mut coeffs = Vec::with_capacity(tsp);
            coeffs.push(tspa_crypto::random_scalar(&mut rng));
            for _ in 1..tsp {
                coeffs.push(tspa_crypto::random_scalar(&mut rng));
            }
            let x = Scalar::from(1u64);

            for _ in 0..warmup {
                let s = tspa_crypto::eval_poly(&coeffs, x);
                black_box(s);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let s = tspa_crypto::eval_poly(&coeffs, x);
                black_box(s);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(
                out,
                scheme,
                "prim",
                "PolyEval_degree_t_minus_1",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &compute_stats(xs),
            )?;
        }
    }

    Ok(())
}

/// Main entry point for benchmark suite
fn main() -> std::io::Result<()> {
    // Default configuration
    let mut scheme: String = "all".to_string();
    let mut nsp_list: Vec<usize> = vec![20, 40, 60, 80, 100];
    let mut tsp_abs: Option<Vec<usize>> = None;
    let mut tsp_pct: Option<Vec<u32>> = Some(vec![20, 40, 60, 80, 100]);

    let mut sample_size: usize = 2000;
    let mut warmup_iters: usize = 300;
    let mut out_path: String = "full_bench.dat".to_string();
    let mut rng_in_timed: bool = false;

    // ===== COMMAND-LINE PARSING =====
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
            "--sample-size" => {
                sample_size = args.next().expect("missing --sample-size").parse().unwrap()
            }
            "--warmup-iters" => {
                warmup_iters = args.next().expect("missing --warmup-iters").parse().unwrap()
            }
            "--out" => out_path = args.next().expect("missing --out"),
            "--rng-in-timed" | "--rng" => rng_in_timed = true,
            "--bench" => {
                let _ = args.next();
            } // tolerate cargo/libtest noise
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    let file = File::create(out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;
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

    // ===== RUN BENCHMARKS =====
    for (nsp, tsp) in points {
        if scheme == "all" || scheme == "upspa" {
            bench_upspa(nsp, tsp, warmup_iters, sample_size, rng_in_timed, &mut out)?;
            out.flush()?;
        }
        if scheme == "all" || scheme == "tspa" {
            bench_tspa(nsp, tsp, warmup_iters, sample_size, rng_in_timed, &mut out)?;
            out.flush()?;
        }

        eprintln!("done nsp={nsp} tsp={tsp} scheme={scheme} rng_in_timed={rng_in_timed}");
    }

    Ok(())
}
