#![allow(clippy::needless_range_loop)]

use crate::crypto;
use crate::crypto::CtBlob;

use blake3;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box; // ✅ added

pub const CIPHERID_PT_LEN: usize = 96; // Sid(32) || Rsp(32) || FK(32)
pub const CIPHERSP_PT_LEN: usize = 40; // Rlsj(32) || ctr(u64=8)

/// Benchmark fixture = “everything the user can fetch from servers + public constants”.
#[derive(Clone)]
pub struct Fixture {
    pub nsp: usize,
    pub tsp: usize,

    pub uid: Vec<u8>,
    pub lsj: Vec<u8>,
    pub password: Vec<u8>,
    pub new_password: Vec<u8>,

    // ✅ store password point once (avoid re-hash per iteration)
    pub pwd_point: RistrettoPoint,

    // TOPRF shares on servers (id -> share scalar). Created for fixture.
    pub shares: Vec<(u32, Scalar)>,
    pub ids_for_t: Vec<u32>, // typically [1..=tsp]
    pub lagrange_at_zero: Vec<Scalar>,

    // Stored at SPs from setup
    pub cipherid_aad: Vec<u8>,
    pub cipherid: CtBlob<CIPHERID_PT_LEN>,

    // Stored at SPs from registration/updates (for authentication benchmark)
    pub ciphersp_aad: Vec<u8>,
    pub ciphersp_per_sp: Vec<CtBlob<CIPHERSP_PT_LEN>>, // length = nsp

    // σ stored at SPs (verification key for password-update signatures)
    pub sig_pk_bytes: [u8; 32],

    // Paper-style: SecretUpdate assumes Authenticate already produced (Rlsj, ctr).
    pub cached_rlsj: [u8; 32],
    pub cached_ctr: u64,
}

/// Per-iteration data: what the client gets back from servers during TOPRF evaluation.
/// For grid/compute-only benchmarks, we generate partials locally.
pub struct IterData {
    pub r: Scalar,
    pub partials: Vec<RistrettoPoint>, // length = tsp
}

/// Build a reproducible fixture for (nsp, tsp).
pub fn make_fixture(nsp: usize, tsp: usize) -> Fixture {
    assert!(tsp >= 1 && tsp <= nsp);

    let seed = {
        let mut h = blake3::Hasher::new();
        h.update(b"uptspa/fixture_seed/v3");
        h.update(&nsp.to_le_bytes());
        h.update(&tsp.to_le_bytes());
        let out = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(out.as_bytes());
        s
    };
    let mut rng = ChaCha20Rng::from_seed(seed);

    let new_password = b"new benchmark password".to_vec();
    let uid = b"user123".to_vec();
    let lsj = b"LS1".to_vec();
    let password = b"benchmark password".to_vec();

    // TOPRF key generation (fixture-only).
    let (master_sk, shares) = crypto::toprf_gen(nsp, tsp, &mut rng);

    // ✅ compute and store pwd_point once
    let pwd_point = crypto::hash_to_point(&password);

    // “True” OPRF output using master key (fixture-only).
    let y = &pwd_point * master_sk;
    let oprf_out = crypto::oprf_finalize(&password, &y);

    // --- NO KDF ---
    let state_key: [u8; 32] = oprf_out;

    // FK independent of password
    let mut fk = [0u8; 32];
    rng.fill_bytes(&mut fk);

    // Ed25519 signing key stored inside cipherid plaintext
    let sid: SigningKey = SigningKey::generate(&mut rng);
    let sid_bytes = sid.to_bytes();
    let sig_pk_bytes: [u8; 32] = sid.verifying_key().to_bytes();

    // Rsp nonce stored inside cipherid plaintext
    let mut rsp = [0u8; 32];
    rng.fill_bytes(&mut rsp);

    // Build cipherid plaintext: Sid||Rsp||FK
    let mut cipherid_pt = [0u8; CIPHERID_PT_LEN];
    cipherid_pt[0..32].copy_from_slice(&sid_bytes);
    cipherid_pt[32..64].copy_from_slice(&rsp);
    cipherid_pt[64..96].copy_from_slice(&fk);

    let cipherid_aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(&uid);
        aad.extend_from_slice(b"|cipherid");
        aad
    };

    let cipherid =
        crypto::xchacha_encrypt_detached(&state_key, &cipherid_aad, &cipherid_pt, &mut rng);

    // Authentication fixture: create one stored ciphersp per SP (identical here).
    let ciphersp_aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(&uid);
        aad.extend_from_slice(b"|ciphersp");
        aad
    };

    let mut rlsj = [0u8; 32];
    rng.fill_bytes(&mut rlsj);
    let ctr: u64 = 0;

    let mut ciphersp_pt = [0u8; CIPHERSP_PT_LEN];
    ciphersp_pt[0..32].copy_from_slice(&rlsj);
    ciphersp_pt[32..40].copy_from_slice(&ctr.to_le_bytes());

    let one_ciphersp =
        crypto::xchacha_encrypt_detached(&fk, &ciphersp_aad, &ciphersp_pt, &mut rng);
    let ciphersp_per_sp = vec![one_ciphersp; nsp];

    // IDs used for threshold combine: choose first tsp servers: 1..=tsp
    let ids_for_t: Vec<u32> = (1..=tsp as u32).collect();
    let lagrange_at_zero = crypto::lagrange_coeffs_at_zero(&ids_for_t);

    Fixture {
        nsp,
        tsp,
        uid,
        lsj,
        password,
        new_password,
        pwd_point, // ✅ stored
        shares,
        ids_for_t,
        lagrange_at_zero,
        cipherid_aad,
        cipherid,
        ciphersp_aad,
        ciphersp_per_sp,
        sig_pk_bytes,
        cached_rlsj: rlsj,
        cached_ctr: ctr,
    }
}

/// Compute-only generation of TOPRF “server responses” (no network).
pub fn make_iter_data(fx: &Fixture, rng: &mut impl RngCore) -> IterData {
    let r = crypto::random_scalar(rng);

    // ✅ no re-hash per iteration
    let blinded = &fx.pwd_point * r;

    let mut partials = Vec::with_capacity(fx.tsp);
    for id in fx.ids_for_t.iter().copied() {
        let share = fx.shares[(id - 1) as usize].1;
        partials.push(blinded * share);
    }

    IterData { r, partials }
}

/// Common “recover state” used by both registration + authentication.
/// ✅ counts blind inside timed region.
// fn recover_state_user_side(fx: &Fixture, it: &IterData) -> ([u8; 32], [u8; 32], SigningKey) {
//     // ✅ ensure blind is included in the timed region (even if partials were prepared outside timing)
//     let b = &fx.pwd_point * it.r;
//     black_box(b);

//     let oprf_out =
//         crypto::toprf_client_eval(&fx.password, it.r, &it.partials, &fx.lagrange_at_zero);

//     // --- NO KDF ---
//     let state_key: [u8; 32] = oprf_out;

//     let pt = crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
//         .expect("cipherid must decrypt if TOPRF is correct");

//     let mut sid_bytes = [0u8; 32];
//     sid_bytes.copy_from_slice(&pt[0..32]);

//     let mut rsp = [0u8; 32];
//     rsp.copy_from_slice(&pt[32..64]);

//     let mut fk = [0u8; 32];
//     fk.copy_from_slice(&pt[64..96]);

//     let sid = SigningKey::from_bytes(&sid_bytes);
//     (rsp, fk, sid)
// }

/// Variant returning decrypted cipherid plaintext (useful for password update).
/// ✅ counts blind inside timed region.
fn recover_state_and_cipherid_pt_user_side(
    fx: &Fixture,
    it: &IterData,
) -> ([u8; CIPHERID_PT_LEN], [u8; 32], [u8; 32], SigningKey) {
    // ✅ ensure blind is included in the timed region
    let b = &fx.pwd_point * it.r;
    black_box(b);

    let oprf_out =
        crypto::toprf_client_eval(&fx.password, it.r, &it.partials, &fx.lagrange_at_zero);
    let state_key: [u8; 32] = oprf_out;

    let pt = crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
        .expect("cipherid must decrypt if TOPRF is correct");

    let mut sid_bytes = [0u8; 32];
    sid_bytes.copy_from_slice(&pt[0..32]);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&pt[32..64]);

    let mut fk = [0u8; 32];
    fk.copy_from_slice(&pt[64..96]);

    let sid = SigningKey::from_bytes(&sid_bytes);
    (pt, rsp, fk, sid)
}

// ============================================================================
// Grid / compute-only client-side benchmarks (ALL include TOPRF via recover_state_*)
// ============================================================================

// pub fn registration_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
//     let (rsp, fk, _sid) = recover_state_user_side(fx, it);

//     let mut acc = blake3::Hasher::new();
//     acc.update(b"uptspa/registration/acc/v1");

//     for i in 1..=fx.nsp {
//         let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
//         acc.update(suid.as_ref());
//     }

//     let mut seed = it.r.to_bytes();
//     seed[0] ^= 0xA5;
//     let mut rng = ChaCha20Rng::from_seed(seed);

//     let mut rlsj = [0u8; 32];
//     rng.fill_bytes(&mut rlsj);
//     let ctr: u64 = 0;

//     let mut pt = [0u8; CIPHERSP_PT_LEN];
//     pt[0..32].copy_from_slice(&rlsj);
//     pt[32..40].copy_from_slice(&ctr.to_le_bytes());

//     let ciphersp = crypto::xchacha_encrypt_detached(&fk, &fx.ciphersp_aad, &pt, &mut rng);

//     let vinfo = crypto::hash_vinfo(&rlsj, &fx.lsj);

//     acc.update(vinfo.as_ref());
//     acc.update(&ciphersp.nonce);
//     acc.update(&ciphersp.ct);
//     acc.update(&ciphersp.tag);

//     let out = acc.finalize();
//     let mut r = [0u8; 32];
//     r.copy_from_slice(out.as_bytes());
//     r
// }

pub fn registration_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    // Recover (Rsp, K0=fk, signing key) using TOPRF + decrypt(cid)
    let (rsp, fk, _sid) = recover_state_user_side(fx, it);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/registration/acc/v1");

    // Compute SUid_{i,j} for ALL providers (nsp of them)
    for i in 1..=fx.nsp {
        let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // Create initial per-login-server secret and ctr=0, encrypt once under K0
    let mut seed = it.r.to_bytes();
    seed[0] ^= 0xA5;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut rlsj = [0u8; 32];
    rng.fill_bytes(&mut rlsj);
    let ctr: u64 = 0;

    let mut pt = [0u8; CIPHERSP_PT_LEN];
    pt[0..32].copy_from_slice(&rlsj);
    pt[32..40].copy_from_slice(&ctr.to_le_bytes());

    let cj = crypto::xchacha_encrypt_detached(&fk, &fx.ciphersp_aad, &pt, &mut rng);
    let vinfo = crypto::hash_vinfo(&rlsj, &fx.lsj);

    acc.update(vinfo.as_ref());
    acc.update(&cj.nonce);
    acc.update(&cj.ct);
    acc.update(&cj.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}


// pub fn authentication_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
//     let (rsp, fk, _sid) = recover_state_user_side(fx, it);

//     let mut acc = blake3::Hasher::new();
//     acc.update(b"uptspa/authentication/acc/v3");

//     for i in 1..=fx.nsp {
//         let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
//         acc.update(suid.as_ref());
//     }

//     let blob = &fx.ciphersp_per_sp[0];
//     let pt = crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob)
//         .expect("ciphersp must decrypt");

//     let mut rlsj = [0u8; 32];
//     rlsj.copy_from_slice(&pt[0..32]);

//     let mut ctr_bytes = [0u8; 8];
//     ctr_bytes.copy_from_slice(&pt[32..40]);
//     let ctr = u64::from_le_bytes(ctr_bytes);

//     let vinfo_prime = crypto::hash_vinfo(&rlsj, &fx.lsj);

//     acc.update(&ctr.to_le_bytes());
//     acc.update(vinfo_prime.as_ref());

//     let out = acc.finalize();
//     let mut r = [0u8; 32];
//     r.copy_from_slice(out.as_bytes());
//     r
// }

pub fn secret_update_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    // 1 decrypt for cid happens inside recover_state_user_side (t+1 total after we decrypt t cj below)
    let (rsp, fk, _sid) = recover_state_user_side(fx, it);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/secret_update/acc/v3");

    for i in 1..=fx.nsp {
        let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // Decrypt t cj records and select freshest by ctr (maxctr)
    let mut old_ctr: u64 = 0;
    let mut old_rlsj = [0u8; 32];

    for &id in fx.ids_for_t.iter() {
        let blob = &fx.ciphersp_per_sp[(id - 1) as usize];
        let pt = crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob)
            .expect("ciphersp must decrypt");

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

    let vinfo_prime = crypto::hash_vinfo(&old_rlsj, &fx.lsj);

    let mut seed = it.r.to_bytes();
    seed[0] ^= 0x3C;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut new_rlsj = [0u8; 32];
    rng.fill_bytes(&mut new_rlsj);
    let new_ctr = old_ctr.wrapping_add(1);

    let mut pt = [0u8; CIPHERSP_PT_LEN];
    pt[0..32].copy_from_slice(&new_rlsj);
    pt[32..40].copy_from_slice(&new_ctr.to_le_bytes());

    let newciphersp = crypto::xchacha_encrypt_detached(&fk, &fx.ciphersp_aad, &pt, &mut rng);
    let newvinfo = crypto::hash_vinfo(&new_rlsj, &fx.lsj);

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


pub fn password_update_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    let (cipherid_pt, _rsp, _fk, sid) = recover_state_and_cipherid_pt_user_side(fx, it);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/password_update/acc/v1");

    let mut seed = it.r.to_bytes();
    seed[0] ^= 0x77;
    let mut rng = ChaCha20Rng::from_seed(seed);

    // NOTE: original code had a confusing double-keygen; keep your fixed deterministic behavior:
    let mut rng2 = ChaCha20Rng::from_seed(seed);
    let (new_master_sk, new_shares) = crypto::toprf_gen(fx.nsp, fx.tsp, &mut rng2);

    let p_new = crypto::hash_to_point(&fx.new_password);
    let y_new = p_new * new_master_sk;
    let new_state_key: [u8; 32] = crypto::oprf_finalize(&fx.new_password, &y_new);

    let newcipherid =
        crypto::xchacha_encrypt_detached(&new_state_key, &fx.cipherid_aad, &cipherid_pt, &mut rng2);

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

fn recover_state_user_side(fx: &Fixture, it: &IterData) -> ([u8; 32], [u8; 32], SigningKey) {
    // Count blind in timed region (even though partials were prepared outside timing)
    let b = &fx.pwd_point * it.r;
    black_box(b);

    // TOPRF from partials ONLY: combine + unblind + finalize
    let oprf_out = crypto::toprf_client_eval_from_partials(
        &fx.password,
        it.r,
        &it.partials,
        &fx.lagrange_at_zero,
    );

    let state_key: [u8; 32] = oprf_out;

    let pt = crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
        .expect("cipherid must decrypt if TOPRF is correct");

    let mut sid_bytes = [0u8; 32];
    sid_bytes.copy_from_slice(&pt[0..32]);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&pt[32..64]);

    let mut fk = [0u8; 32];
    fk.copy_from_slice(&pt[64..96]);

    let sid = SigningKey::from_bytes(&sid_bytes);
    (rsp, fk, sid)
}

pub fn authentication_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    // 1 decrypt for cid happens inside recover_state_user_side (t+1 total after we decrypt t cj below)
    let (rsp, fk, _sid) = recover_state_user_side(fx, it);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/authentication/acc/v4");

    // Hash SUIDs for contacted providers (t of them)
    for &id in fx.ids_for_t.iter() {
        let suid = crypto::hash_suid(&rsp, &fx.lsj, id);
        acc.update(suid.as_ref());
    }

    // Decrypt t cj records and select the freshest by ctr (maxctr)
    let mut best_ctr: u64 = 0;
    let mut best_rlsj = [0u8; 32];

    for &id in fx.ids_for_t.iter() {
        let blob = &fx.ciphersp_per_sp[(id - 1) as usize];
        let pt = crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob)
            .expect("ciphersp must decrypt");

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

    let vinfo_prime = crypto::hash_vinfo(&best_rlsj, &fx.lsj);

    acc.update(&best_ctr.to_le_bytes());
    acc.update(vinfo_prime.as_ref());

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}


// ============================================================================
// Setup protocol (user-side) benchmark: Protocol 1 Π_Setup
// ============================================================================

#[derive(Clone)]
pub struct SetupBenchFixture {
    pub uid: Vec<u8>,
    pub password: Vec<u8>,
    pub pwd_point: RistrettoPoint,
    pub cipherid_aad: Vec<u8>,
}

/// Build a tiny bench fixture with constant uid/password (no network).
pub fn make_setup_bench_fixture() -> SetupBenchFixture {
    let uid = b"user123".to_vec();
    let password = b"benchmark password".to_vec();
    let pwd_point = crypto::hash_to_point(&password);

    let cipherid_aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(&uid);
        aad.extend_from_slice(b"|cipherid");
        aad
    };

    SetupBenchFixture { uid, password, pwd_point, cipherid_aad }
}

/// User-side Setup Π_Setup (NO network / NO server DB):
/// 1) sample Rsp
/// 2) TOPRFKeyGen -> (K, {k_i})
/// 3) SignKeyGen -> (ssk, svk) ; σ = svk
/// 4) sample K0 (32B)
/// 5) cid = Enc_{F_K(pwd)}(ssk || Rsp || K0)
/// 6) prepare per-SP payload (Uid, σ, cid, k_i)  [no send]
///
/// Returns a 32B digest so the compiler can't optimize away work.
pub fn setup_user_side_bench<R: RngCore + rand_core::CryptoRng>(
    fx: &SetupBenchFixture,
    nsp: usize,
    tsp: usize,
    rng: &mut R,
) -> [u8; 32] {
    assert!(tsp >= 1 && tsp <= nsp);

    // 1) Rsp
    let mut rsp = [0u8; 32];
    rng.fill_bytes(&mut rsp);

    // 2) TOPRFKeyGen
    let (master_sk, shares) = crypto::toprf_gen(nsp, tsp, rng);

    // 3) SignKeyGen
    let sid: SigningKey = SigningKey::generate(rng);
    let sid_bytes = sid.to_bytes();
    let sig_pk_bytes: [u8; 32] = sid.verifying_key().to_bytes(); // σ = svk

    // 4) K0 (32B)
    let mut k0 = [0u8; 32];
    rng.fill_bytes(&mut k0);

    // 5) cid = Enc_{F_K(pwd)}(ssk || Rsp || K0)
    //    F_K(pwd) computed as OPRF finalize with master key (fixture-style)
    let y = &fx.pwd_point * master_sk;
    let state_key: [u8; 32] = crypto::oprf_finalize(&fx.password, &y);

    let mut cipherid_pt = [0u8; CIPHERID_PT_LEN];
    cipherid_pt[0..32].copy_from_slice(&sid_bytes);
    cipherid_pt[32..64].copy_from_slice(&rsp);
    cipherid_pt[64..96].copy_from_slice(&k0);

    let cid = crypto::xchacha_encrypt_detached(&state_key, &fx.cipherid_aad, &cipherid_pt, rng);

    // 6) Prepare payloads (Uid, σ, cid, k_i) — no send.
    //    We hash everything into an accumulator so nothing is optimized out.
    let mut h = blake3::Hasher::new();
    h.update(b"upspa/setup/bench/v1");
    h.update(&fx.uid);
    h.update(&sig_pk_bytes);
    h.update(&cid.nonce);
    h.update(&cid.ct);
    h.update(&cid.tag);

    for (id, share) in shares.iter() {
        h.update(&id.to_le_bytes());
        h.update(&share.to_bytes());
    }

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    black_box(r);
    r
}
