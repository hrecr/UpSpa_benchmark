//! This module implements the UPSPA protocol, which provides:
//! - Threshold OPRF (Oblivious Pseudo-Random Function) for password-based encryption
//! - Searchable encryption for protected account identifiers
//! - Support for server-side password updates with Shamir secret sharing
//! - User-side secret and password updates with verification via Lagrange coefficients

//! Key cryptographic primitives used:
//! - Curve25519 elliptic curve for ECC operations (curve25519_dalek library)
//! - XChaCha20-Poly1305 for authenticated encryption
//! - BLAKE3 for cryptographic hashing
//! - Ed25519 for digital signatures
//! - ChaCha20 for deterministic RNG seeding
#![allow(clippy::needless_range_loop)]

use crate::crypto;
use crate::crypto::CtBlob;

use blake3;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;


// Constants for ciphertext component sizes


/// Size of plaintext packed in cipherid (SigningKey || Rsp || K0)
/// - SigningKey bytes: 32
/// - Rsp (random bytes): 32
/// - K0 (state key derivative): 32
/// Total: 96 bytes
pub const CIPHERID_PT_LEN: usize = 96;

/// Size of plaintext packed in ciphersp per storage provider
/// - Random LSJ value (rlsj): 32 bytes
/// - Counter (ctr): 8 bytes
/// Total: 40 bytes
pub const CIPHERSP_PT_LEN: usize = 40;


// Fixture: Persistent Server-Side State for Benchmark Simulation


/// Complete benchmark fixture representing persistent data on servers and cached values.
/// This simulates the state that would be stored across multiple UPSPA interactions.
#[derive(Clone)]
pub struct Fixture {
    /// nsp: Number of Storage Providers (servers holding encrypted user data)
    pub nsp: usize,
    /// tsp: Threshold - number of servers needed to reconstruct the password
    /// Property: 1 <= tsp <= nsp (typically tsp = ceil(nsp/2) for majority threshold)
    pub tsp: usize,
    /// uid: User Identity (typically username or account identifier)
    pub uid: Vec<u8>,
    /// lsj: Label for searchable encryption (site/service identifier)
    pub lsj: Vec<u8>,
    /// password: Original password used for OPRF and state derivation
    pub password: Vec<u8>,
    /// new_password: Replacement password for password update operations
    pub new_password: Vec<u8>,
    /// pwd_point: Hash of password to elliptic curve point (H(password))
    /// Used as base point for TOPRF computations
    pub pwd_point: RistrettoPoint,
    /// new_pwd_point: Hash of new_password to elliptic curve point (H(new_password))
    /// Used for TOPRF computations during password update (second TOPRF round)
    pub new_pwd_point: RistrettoPoint,
    /// shares: Shamir secret shares of the TOPRF master secret
    /// Each (id, scalar) is a share, where id is the share index (1..nsp)
    /// Total nsp shares exist; any tsp of them can reconstruct the secret
    pub shares: Vec<(u32, Scalar)>,
    /// ids_for_t: Share indices used for current benchmark (typically 1..=tsp)
    pub ids_for_t: Vec<u32>,
    /// lagrange_at_zero: Lagrange basis polynomials evaluated at zero
    /// Used to combine tsp shares into the master secret via: K = sum(lagrange[i] * partial_i)
    pub lagrange_at_zero: Vec<Scalar>,
    /// cipherid_aad: Additional Authenticated Data for cipherid encryption
    /// Generally: uid || "cipherid"
    pub cipherid_aad: Vec<u8>,
    /// cipherid: Encrypted signing key, Rsp, and K0 under state_key = F_K(password)
    /// Plaintext: sid_bytes || rsp || fk
    pub cipherid: CtBlob<CIPHERID_PT_LEN>,
    /// ciphersp_aad: Additional Authenticated Data for per-SP cipherspaces
    /// Generally: uid || "ciphersp"
    pub ciphersp_aad: Vec<u8>,
    /// ciphersp_per_sp: Per-SP ciphertext blobs (one per storage provider)
    /// Each contains encrypted (rlsj || counter) under the file key fk
    /// Length: nsp (one ciphertext per server)
    pub ciphersp_per_sp: Vec<CtBlob<CIPHERSP_PT_LEN>>,
    /// sig_pk_bytes: Public key for signing (Ed25519), used to verify password updates
    pub sig_pk_bytes: [u8; 32],
    /// cached_rlsj: Cached random LSJ value (facilitates secret/password updates)
    pub cached_rlsj: [u8; 32],
    /// cached_ctr: Cached counter value for version control of ciphersp updates
    pub cached_ctr: u64,
}

// Per-Iteration Data: User-Side Randomness for Each UPSPA Operation

/// Transient randomness generated fresh for each UPSPA operation (registration, auth, etc.)
/// Contains the blinding factor and partial evaluations needed for one complete protocol run.
pub struct IterData {
    /// r: User's random blinding factor (Zp scalar)
    /// Used to blind the password hash: r * H(password)
    /// Properties:
    /// - Sampled uniformly at random from Z_p each operation
    /// - Must be secret (never transmitted to servers)
    /// - MUST be different for each registration/authentication
    pub r: Scalar,
    /// partials: Partial TOPRF evaluations from each server
    /// partials[i] = r * sk_i * H(password), where sk_i is share i of the master secret
    /// Computed by servers during TOPRF evaluation round
    /// Length: tsp (number of servers in the threshold)
    pub partials: Vec<RistrettoPoint>,
    /// r_new: Fresh random blinding factor for the NEW password (second TOPRF round)
    /// Used only during password update: r_new * H(new_password)
    pub r_new: Scalar,
    /// partials_new: Partial TOPRF evaluations for the NEW password
    /// partials_new[i] = r_new * sk_i * H(new_password)
    /// Length: tsp
    pub partials_new: Vec<RistrettoPoint>,
}

// SETUP: Create Fixture and Per-Iteration Data

/// Initialize a complete UPSPA fixture with all server-side state.
/// Simulates the initial setup phase where:
/// 1. Password is hashed to curve point
/// 2. TOPRF master secret is sampled and shared among servers (Shamir split)
/// 3. Signing key and initial file key are generated
/// 4. Ciphertexts are encrypted for each server
///
/// # Arguments
/// * `nsp` - Number of Storage Providers (total servers)
/// * `tsp` - Threshold (minimum servers needed to decrypt/evaluate TOPRF)
///
/// # Panics
/// If tsp < 1 or tsp > nsp
///
/// # Returns
/// Complete Fixture with all initialized state ready for protocol operations
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
    let (master_sk, shares) = crypto::toprf_gen(nsp, tsp, &mut rng);
    let pwd_point = crypto::hash_to_point(&password);
    let new_pwd_point = crypto::hash_to_point(&new_password);
    let y = &pwd_point * master_sk;
    let oprf_out = crypto::oprf_finalize(&password, &y);
    let state_key: [u8; 32] = oprf_out;
    let mut fk = [0u8; 32];
    rng.fill_bytes(&mut fk);
    let sid: SigningKey = SigningKey::generate(&mut rng);
    let sid_bytes = sid.to_bytes();
    let sig_pk_bytes: [u8; 32] = sid.verifying_key().to_bytes();
    let mut rsp = [0u8; 32];
    rng.fill_bytes(&mut rsp);
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
    let ids_for_t: Vec<u32> = (1..=tsp as u32).collect();
    let lagrange_at_zero = crypto::lagrange_coeffs_at_zero(&ids_for_t);
    Fixture {
        nsp,
        tsp,
        uid,
        lsj,
        password,
        new_password,
        pwd_point,
        new_pwd_point,
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

/// Generate fresh per-iteration randomness for one UPSPA operation.
/// Creates the blinding factor and requests partial TOPRF evaluations.
///
/// # Arguments
/// * `fx` - The fixture containing the password point and shares
/// * `rng` - Random number generator for sampling the blinding factor
///
/// # Returns
/// IterData with:
/// - r: Fresh random blinding scalar
/// - partials: Partial TOPRF evaluations (simulated from all tsp servers)
pub fn make_iter_data(fx: &Fixture, rng: &mut impl RngCore) -> IterData {
    // First TOPRF round data: current password
    let r = crypto::random_scalar(rng);
    let blinded = &fx.pwd_point * r;
    let mut partials = Vec::with_capacity(fx.tsp);
    for id in fx.ids_for_t.iter().copied() {
        let share = fx.shares[(id - 1) as usize].1;
        partials.push(blinded * share);
    }

    // Second TOPRF round data: NEW password (used only by password update)
    let r_new = crypto::random_scalar(rng);
    let blinded_new = &fx.new_pwd_point * r_new;
    let mut partials_new = Vec::with_capacity(fx.tsp);
    for id in fx.ids_for_t.iter().copied() {
        let share = fx.shares[(id - 1) as usize].1;
        partials_new.push(blinded_new * share);
    }

    IterData {
        r,
        partials,
        r_new,
        partials_new,
    }
}



// RECOVERY: Decrypt State from Ciphertext (Internal Helper)

/// Decryption process:
/// 1. Combine partial TOPRF evaluations using Lagrange interpolation
/// 2. Compute state_key = OPRF_finalize(password, combined_evaluation)
/// 3. Decrypt cipherid under state_key
/// 4. Extract components (signing_key, Rsp, K0) from plaintext

fn recover_state_and_cipherid_pt_user_side(
    fx: &Fixture,
    it: &IterData,
) -> ([u8; CIPHERID_PT_LEN], [u8; 32], [u8; 32], SigningKey) {
    let b = &fx.pwd_point * it.r;
    black_box(b);
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
    (pt, rsp, fk, sid)
}


// REGISTRATION: Compute user's registration verification (Π_Reg_U)

/// User-side registration: Verify account setup by computing registration credential.
/// This operation:
/// 1. Recovers Rsp and file key (fk) from decrypted cipherid
/// 2. Computes user identity hashes (suid) for each server
/// 3. Derives per-SP cipherspace (rlsj, counter)
/// 4. Hashes all components to produce registration proof
pub fn registration_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    let (rsp, fk, _sid) = recover_state_user_side(fx, it);
    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/registration/acc/v1");
    for i in 1..=fx.nsp {
        let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }
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


// SECRET UPDATE: Rotate account credentials while preserving password (Π_SecUp_U)

/// Protocol steps:
/// 1. Recover current Rsp and file key (fk)
/// 2. Hash all service identifiers (suid) with current Rsp
/// 3. Decrypt ceil(n/t) ciphersp blobs to find the latest counter
/// 4. Derive new random LSJ (rlsj_prime) and increment counter
/// 5. Encrypt new state under new file key
/// 6. Hash all updates to produce secret update credential

pub fn secret_update_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    // 1 decrypt for cid happens inside recover_state_user_side (t+1 total after we decrypt t cj below)
    let (rsp, fk, _sid) = recover_state_user_side(fx, it);
    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/secret_update/acc/v3");
    for i in 1..=fx.nsp {
        let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }
    let mut old_ctr: u64 = 0;
    let mut old_rlsj = [0u8; 32];
    let m = (fx.nsp + fx.tsp - 1) / fx.tsp; // ceil(n/t)
    for j in 0..m {
        let id_usize = 1 + j * fx.tsp;
        if id_usize > fx.nsp {
        break;
    }
        let blob = &fx.ciphersp_per_sp[(id_usize - 1) as usize];
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


// PASSWORD UPDATE: Change password by re-wrapping cipherid under new password (Π_PwdUp_U)

/// High level (client-side):
/// 1) Run TOPRF with the *current* password to decrypt `cipherid` and recover the signing key.
/// 2) Run TOPRF again with the *new* password to derive a fresh state key.
/// 3) Re-encrypt the SAME `cipherid` plaintext under the new state key, producing `cid_new`.
/// 4) Produce ONE Ed25519 signature over (cid_new || time) and send the same tuple to all SPs.
pub fn password_update_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    // 1) Recover (SigningKey || Rsp || fk) under the OLD password-derived state key.
    let (cipherid_pt, _rsp, _fk, sid) = recover_state_and_cipherid_pt_user_side(fx, it);

    // 2) TOPRF with the NEW password to derive a fresh state key.
    // (Server partials for the new password are provided via IterData.)
    let b_new = &fx.new_pwd_point * it.r_new;
    black_box(b_new);

    let new_state_key: [u8; 32] = crypto::toprf_client_eval_from_partials(
        &fx.new_password,
        it.r_new,
        &it.partials_new,
        &fx.lagrange_at_zero,
    );

    // 3) Re-encrypt the SAME cipherid plaintext under the new password-derived key => cid_new.
    let mut seed = it.r.to_bytes();
    seed[0] ^= 0x77;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let cid_new =
        crypto::xchacha_encrypt_detached(&new_state_key, &fx.cipherid_aad, &cipherid_pt, &mut rng);

    // 4) Sign ONCE (no per-provider index).
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

    // 5) Benchmark-only accumulator.
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

// INTERNAL RECOVERY: Extract decrypted state for further operations

fn recover_state_user_side(fx: &Fixture, it: &IterData) -> ([u8; 32], [u8; 32], SigningKey) {
    let b = &fx.pwd_point * it.r;
    black_box(b);
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



// AUTHENTICATION: Verify user and retrieve searchable data (Π_Auth_U)
/// User-side authentication: Prove knowledge of account without sending password.
/// Servers use this credential to:
/// 1. Verify user knows the account secret
/// 2. Retrieve encrypted search indices (suid) for data lookup
/// 3. Decrypt user's encrypted storage (using same cryptographic material)

/// Protocol flow:
/// 1. Recover Rsp using blinded TOPRF evaluation
/// 2. Hash n service identifiers (suid) with Rsp
/// 3. Decrypt up to ceil(n/t) ciphersp to find latest counter and LSJ
/// 4. Hash the version info to prove freshness
/// 5. Return counter + vinfo hash as authentication credential

pub fn authentication_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    let (rsp, fk, _sid) = recover_state_user_side(fx, it);
    // m = ceil(n/t)
    let m = (fx.nsp + fx.tsp - 1) / fx.tsp;
    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/authentication/acc/v5");

    // (n) suid hashes
    for i in 1..=fx.nsp {
        let suid = crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    // decrypt only m ciphersp blobs (instead of t)
    let mut best_ctr: u64 = 0;
    let mut best_rlsj = [0u8; 32];

    for j in 0..m {
        let id_usize = 1 + j * fx.tsp; 
        if id_usize > fx.nsp {
            break;
        }
        let blob = &fx.ciphersp_per_sp[id_usize - 1];
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


// SETUP BENCHMARK FIXTURE: Minimal State for Setup Phase Benchmarking
/// Used to measure:
/// - Password hashing to curve point (H(password))
/// - TOPRF key generation and sharing
/// - Signing key generation
/// - AEAD encryption of account state
/// - Hash computation of setup proof
#[derive(Clone)]
pub struct SetupBenchFixture {
    /// uid: User identity
    pub uid: Vec<u8>,
    /// password: Account password
    pub password: Vec<u8>,
    /// pwd_point: Cached hash of password to elliptic curve (optimization for benchmarking)
    pub pwd_point: RistrettoPoint,
    /// cipherid_aad: Additional authenticated data for cipherid encryption
    pub cipherid_aad: Vec<u8>,
}

/// Create lightweight fixture for setup phase benchmarking.
/// Initializes minimal state: password hash, UID, and AAD for cipherid encryption.
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

/// Benchmark the account setup phase.
/// Simulates all work the user performs during initial account creation:
/// 1. Sample random Rsp (random account secret pseudo-seed)
/// 2. Generate TOPRF master secret and split into nsp Shamir shares
/// 3. Generate signing key (sk, vk) for verifying server updates
/// 4. Sample K0 (derivative seed for per-SP file keys)
/// 5. Encrypt {ssk || Rsp || K0} under state_key derived from password
/// 6. Prepare per-SP payloads (Uid, signature_pk, cipherid, share_i)

pub fn setup_user_side_bench<R: RngCore + rand_core::CryptoRng>(
    fx: &SetupBenchFixture,
    nsp: usize,
    tsp: usize,
    rng: &mut R,
) -> [u8; 32] {
    assert!(tsp >= 1 && tsp <= nsp);
    let mut rsp = [0u8; 32];
    rng.fill_bytes(&mut rsp);
    let (master_sk, shares) = crypto::toprf_gen(nsp, tsp, rng);
    let sid: SigningKey = SigningKey::generate(rng);
    let sid_bytes = sid.to_bytes();
    let sig_pk_bytes: [u8; 32] = sid.verifying_key().to_bytes();
    let mut k0 = [0u8; 32];
    rng.fill_bytes(&mut k0);
    let y = &fx.pwd_point * master_sk;
    let state_key: [u8; 32] = crypto::oprf_finalize(&fx.password, &y);
    let mut cipherid_pt = [0u8; CIPHERID_PT_LEN];
    cipherid_pt[0..32].copy_from_slice(&sid_bytes);
    cipherid_pt[32..64].copy_from_slice(&rsp);
    cipherid_pt[64..96].copy_from_slice(&k0);
    let cid = crypto::xchacha_encrypt_detached(&state_key, &fx.cipherid_aad, &cipherid_pt, rng);
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
