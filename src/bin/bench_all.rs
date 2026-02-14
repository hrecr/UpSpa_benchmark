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

// Fixed-nonce AEAD for "no RNG in timed region"
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};

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

/// Fixed-nonce XChaCha20-Poly1305 encrypt for timing without RNG.
/// Output layout matches up_crypto::CtBlob.
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

fn upspa_recover_state_and_cipherid_pt(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
) -> ([u8; 32], [u8; upspa_proto::CIPHERID_PT_LEN]) {
    // include "blind mul" parity (matches your protocol code)
    let b = &fx.pwd_point * it.r;
    black_box(b);

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

/// Deterministically precompute the exact RNG outputs that your reg uses (rlsj then nonce),
/// but do it OUTSIDE the timed region.
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

/// Same idea for secupd: (new_rlsj then nonce) outside timing.
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

/// Precompute pwdupd randomness outside timing:
/// - coeffs (t scalars) for TOPRF polynomial
/// - nonce for newcipherid
fn upspa_precompute_pwdupd_coeffs_and_nonce(r: Scalar, tsp: usize) -> (Vec<Scalar>, [u8; up_crypto::NONCE_LEN]) {
    let mut seed = r.to_bytes();
    seed[0] ^= 0x77;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut coeffs = Vec::with_capacity(tsp);
    for _ in 0..tsp {
        coeffs.push(up_crypto::random_scalar(&mut rng));
    }

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    (coeffs, nonce)
}

/// Match up_crypto::toprf_gen's evaluation method (power-basis eval).
fn eval_poly_pow(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut pow = Scalar::ONE;
    for c in coeffs {
        acc += c * pow;
        pow *= x;
    }
    acc
}

/// UPSPA registration, but with RNG moved out of timed region.
/// We still time TOPRF + cipherid dec + hashes + AEAD enc (but nonce/rlsj already chosen).
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

    // (n) suid hashes
    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // AEAD enc of ciphersp with fixed nonce (no RNG)
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

/// UPSPA secret update, RNG moved out of timed region.
/// (new_rlsj + nonce precomputed; new_ctr still derived from decrypted old ctr inside timing)
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

    // (n) suid hashes
    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // decrypt t ciphersp (same as your protocol)
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

    // AEAD enc with fixed nonce (no RNG)
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

/// UPSPA password update, RNG moved out of timed region:
/// - coeff sampling + newcipherid nonce are precomputed outside timing
/// - share evaluation (n * t field ops) stays in timed region
fn upspa_pwdupd_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    coeffs: &[Scalar],
    newcipherid_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    // recover state + get cipherid_pt + sid (needed for signatures)
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (_rsp, _fk, sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/password_update/acc/v1");

    // master key is a0
    let new_master_sk = coeffs[0];

    // evaluate shares inside timed region (keeps non-RNG cost)
    let mut new_shares: Vec<(u32, Scalar)> = Vec::with_capacity(fx.nsp);
    for i in 1..=fx.nsp {
        let x = Scalar::from(i as u64);
        let s = eval_poly_pow(coeffs, x);
        new_shares.push((i as u32, s));
    }

    // build newcipherid (fixed nonce, no RNG)
    let p_new = up_crypto::hash_to_point(&fx.new_password);
    let y_new = p_new * new_master_sk;
    let new_state_key = up_crypto::oprf_finalize(&fx.new_password, &y_new);

    let newcipherid =
        upspa_aead_encrypt_fixed(&new_state_key, &fx.cipherid_aad, &cipherid_pt, newcipherid_nonce);

    let timestamp: u64 = 0;
    const MSG_LEN: usize = 24 + 96 + 16 + 32 + 8 + 4;

    for (id, share) in new_shares.iter() {
        let i_u32 = *id;
        let share_bytes = share.to_bytes();

        let mut msg = [0u8; MSG_LEN];
        let mut off = 0;
        msg[off..off + 24].copy_from_slice(&newcipherid.nonce);
        off += 24;
        msg[off..off + 96].copy_from_slice(&newcipherid.ct);
        off += 96;
        msg[off..off + 16].copy_from_slice(&newcipherid.tag);
        off += 16;
        msg[off..off + 32].copy_from_slice(&share_bytes);
        off += 32;
        msg[off..off + 8].copy_from_slice(&timestamp.to_le_bytes());
        off += 8;
        msg[off..off + 4].copy_from_slice(&i_u32.to_le_bytes());
        off += 4;

        debug_assert_eq!(off, MSG_LEN);

        let sig = sid.sign(&msg);
        let sig_bytes = sig.to_bytes();

        acc.update(&i_u32.to_le_bytes());
        acc.update(&sig_bytes);
    }

    acc.update(&newcipherid.nonce);
    acc.update(&newcipherid.ct);
    acc.update(&newcipherid.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// UPSPA auth formula-compatible:
/// TOPRF + (ceil(n/t)+1) AE-Dec + (n+1) hash
/// - hashes ALL n suid
/// - decrypts ONLY m = ceil(n/t) ciphersp (plus cipherid)
fn upspa_auth_formula_compatible(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/authentication/acc/formula_v1");

    // (n) suid hashes (NOT t)
    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // decrypt m = ceil(n/t) ciphersp (NOT t)
    let m = (fx.nsp + fx.tsp - 1) / fx.tsp;

    let mut best_ctr: u64 = 0;
    let mut best_rlsj = [0u8; 32];
    for j in 0..m {
        let blob = &fx.ciphersp_per_sp[j];
        let pt = up_crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob).unwrap();

        let mut rlsj = [0u8; 32];
        rlsj.copy_from_slice(&pt[0..32]);
        let mut ctr_bytes = [0u8; 8];
        ctr_bytes.copy_from_slice(&pt[32..40]);
        let ctr = u64::from_le_bytes(ctr_bytes);

        if ctr >= best_ctr {
            best_ctr = ctr;
            best_rlsj = rlsj;
        }
    }

    let vinfo_prime = up_crypto::hash_vinfo(&best_rlsj, &fx.lsj);
    acc.update(&best_ctr.to_le_bytes());
    acc.update(vinfo_prime.as_ref());

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

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

    // RNGs for iter_data outside timed region
    let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/reg_rng/v1", nsp, tsp));
    let mut rng_auth = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/auth_rng/v1", nsp, tsp));
    let mut rng_sec = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/sec_rng/v1", nsp, tsp));
    let mut rng_pwd = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/pwd_rng/v1", nsp, tsp));

    // ---- PROTO reg ----
    {
        // warmup
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
                ([0u8; 32], [0u8; up_crypto::NONCE_LEN]) // unused
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
        write_row(out, scheme, "proto", "reg", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // ---- PROTO auth (your existing function) ----
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
            let _ = upspa_proto::authentication_user_side(&fx, &it);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
            let t0 = Instant::now();
            let outv = upspa_proto::authentication_user_side(&fx, &it);
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(out, scheme, "proto", "auth", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // ---- PROTO secupd ----
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
                ([0u8; 32], [0u8; up_crypto::NONCE_LEN]) // unused
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
        write_row(out, scheme, "proto", "secupd", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // ---- PROTO pwdupd ----
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_pwd);
            let _ = if rng_in_timed {
                upspa_proto::password_update_user_side(&fx, &it)
            } else {
                let (coeffs, nonce) = upspa_precompute_pwdupd_coeffs_and_nonce(it.r, fx.tsp);
                upspa_pwdupd_no_rng(&fx, &it, &coeffs, nonce)
            };
        }

        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_pwd);

            let (coeffs, nonce) = if rng_in_timed {
                (Vec::new(), [0u8; up_crypto::NONCE_LEN]) // unused
            } else {
                upspa_precompute_pwdupd_coeffs_and_nonce(it.r, fx.tsp)
            };

            let t0 = Instant::now();
            let outv = if rng_in_timed {
                upspa_proto::password_update_user_side(&fx, &it)
            } else {
                upspa_pwdupd_no_rng(&fx, &it, &coeffs, nonce)
            };
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(out, scheme, "proto", "pwdupd", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // ---- FORMULA-COMPATIBLE auth (ceil(n/t)+1 AE-Dec, (n+1) hash) ----
    {
        for _ in 0..warmup {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
            let _ = upspa_auth_formula_compatible(&fx, &it);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
            let t0 = Instant::now();
            let outv = upspa_auth_formula_compatible(&fx, &it);
            black_box(outv);
            xs.push(t0.elapsed().as_nanos());
        }
        write_row(out, scheme, "formula", "auth", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // --------------------------
    // Primitives (UPSPA)
    // --------------------------
    {
        // derive rsp/fk once (outside timing) for primitive benches that need them
        let mut rng0 = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/prim/derive/v1", nsp, tsp));
        let it0 = upspa_proto::make_iter_data(&fx, &mut rng0);
        let (state_key0, cipherid_pt0) = upspa_recover_state_and_cipherid_pt(&fx, &it0);
        let (rsp0, fk0, _sid0) = upspa_extract_rsp_fk_sid(&cipherid_pt0);

        // TOPRF (depends on tsp via partial count)
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
            write_row(out, scheme, "prim", "TOPRF_client_eval", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // AEAD dec cipherid
        {
            for _ in 0..warmup {
                let pt = up_crypto::xchacha_decrypt_detached(&state_key0, &fx.cipherid_aad, &fx.cipherid).unwrap();
                black_box(pt);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let pt = up_crypto::xchacha_decrypt_detached(&state_key0, &fx.cipherid_aad, &fx.cipherid).unwrap();
                black_box(pt);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(out, scheme, "prim", "AEAD_DEC_cipherid", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // AEAD dec one ciphersp
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
            write_row(out, scheme, "prim", "AEAD_DEC_ciphersp", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // AEAD enc ciphersp (rng optional)
        {
            let ctr: u64 = 0;
            let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
            pt[0..32].copy_from_slice(&fx.cached_rlsj);
            pt[32..40].copy_from_slice(&ctr.to_le_bytes());

            if rng_in_timed {
                let mut rng = ChaCha20Rng::from_seed(seed_for(b"unified/upspa/prim/aead_enc_rng/v1", nsp, tsp));
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
                write_row(out, scheme, "prim", "AEAD_ENC_ciphersp_with_rng", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
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
                write_row(out, scheme, "prim", "AEAD_ENC_ciphersp_fixed_nonce", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
            }
        }

        // HASH suid
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
            write_row(out, scheme, "prim", "HASH_suid", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // HASH vinfo
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
            write_row(out, scheme, "prim", "HASH_vinfo", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }
    }

    Ok(())
}

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

    // ---- PROTO reg ----
    {
        for _ in 0..warmup {
            if rng_in_timed {
                // includes iter_data generation inside timing (NOTE: includes extra work vs "core")
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
        write_row(out, scheme, "proto", "reg", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // ---- PROTO auth ----
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

        write_row(out, scheme, "proto", "auth", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
    }

    // --------------------------
    // Primitives (TSPA)
    // --------------------------
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

        // HASH storuid
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
            write_row(out, scheme, "prim", "HASH_storuid", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // HASH vinfo
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
            write_row(out, scheme, "prim", "HASH_vinfo", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // OPRF finalize (hash-only)
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
            write_row(out, scheme, "prim", "OPRF_finalize", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // OPRF full eval = MulP + finalize (matches what your TSPA reg does per provider)
        {
            for _ in 0..warmup {
                let y2 = fx.pwd_point * k;
                black_box(y2.compress());
                let outk = tspa_crypto::oprf_finalize(&fx.password, &y2);
                black_box(outk);
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let y2 = fx.pwd_point * k;
                black_box(y2.compress());
                let outk = tspa_crypto::oprf_finalize(&fx.password, &y2);
                black_box(outk);
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(out, scheme, "prim", "OPRF_eval_full", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // MulP
        {
            for _ in 0..warmup {
                let p = fx.pwd_point * k;
                black_box(p.compress());
            }
            let mut xs = Vec::with_capacity(samples);
            for _ in 0..samples {
                let t0 = Instant::now();
                let p = fx.pwd_point * k;
                black_box(p.compress());
                xs.push(t0.elapsed().as_nanos());
            }
            write_row(out, scheme, "prim", "MulP_point_scalar", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // InvS
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
            write_row(out, scheme, "prim", "InvS_scalar_invert", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // FieldOp (mul+add)
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
            write_row(out, scheme, "prim", "FieldOp_mul_add", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // AES-256-CTR XOR 32
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
            write_row(out, scheme, "prim", "AES256CTR_xor_32", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }

        // PolyEval (degree t-1)
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
            write_row(out, scheme, "prim", "PolyEval_degree_t_minus_1", rng_in_timed, nsp, tsp, warmup, &compute_stats(xs))?;
        }
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    // Defaults
    let mut scheme: String = "all".to_string(); // all | upspa | tspa

    let mut nsp_list: Vec<usize> = vec![20, 40, 60, 80, 100];
    let mut tsp_abs: Option<Vec<usize>> = None;
    let mut tsp_pct: Option<Vec<u32>> = Some(vec![20, 40, 60, 80, 100]);

    let mut sample_size: usize = 2000;
    let mut warmup_iters: usize = 300;
    let mut out_path: String = "unified_bench.dat".to_string();

    // RNG in timed region?
    let mut rng_in_timed: bool = false;

    // CLI
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
            "--sample-size" => sample_size = args.next().expect("missing --sample-size").parse().unwrap(),
            "--warmup-iters" => warmup_iters = args.next().expect("missing --warmup-iters").parse().unwrap(),
            "--out" => out_path = args.next().expect("missing --out"),
            "--rng-in-timed" | "--rng" => rng_in_timed = true,
            "--bench" => { let _ = args.next(); } // tolerate cargo/libtest noise
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    let file = File::create(out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;

    // Build points (nsp, tsp)
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
