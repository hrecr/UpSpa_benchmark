use crate::crypto;
use crate::crypto_tspa;
use crate::protocols::tspa as tspa_proto;
use crate::protocols::upspa as upspa_proto;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

/// Compressed Ristretto point size in bytes.
pub const RISTRETTO_BYTES: usize = 32;

/// Network payload sizes (compact constants used by benchmarks).
pub const NET_UPSPA_SETUP_REQ_BYTES: usize = 32 + 32 + 136 + 32 + 4;
/// 1-byte status response for setup.
pub const NET_UPSPA_SETUP_RESP_BYTES: usize = 1;

/// TSPA registration upload payload: stor_uid(32) || k_i(32) || c_i(48).
pub const NET_TSPA_REG_REQ_BYTES: usize = 32 + 32 + 48;
/// 1-byte status response.
pub const NET_TSPA_REG_RESP_BYTES: usize = 1;

/// TSPA auth request: stor_uid(32) || blinded(32).
pub const NET_TSPA_AUTH_REQ_BYTES: usize = 32 + RISTRETTO_BYTES;
/// TSPA auth response: z(32) || ciphertext(48).
pub const NET_TSPA_AUTH_RESP_BYTES: usize = RISTRETTO_BYTES + 48;

/// UpSPA TOPRF request: uid_hash(32) || blinded(32).
pub const NET_UPSPA_TOPRF_REQ_BYTES: usize = 32 + RISTRETTO_BYTES;
/// UpSPA TOPRF response: partial(32).
pub const NET_UPSPA_TOPRF_RESP_BYTES: usize = RISTRETTO_BYTES;

/// UpSPA fetch ciphersp request: suid(32).
pub const NET_UPSPA_GET_CSP_REQ_BYTES: usize = 32;
/// UpSPA fetch ciphersp response: nonce || ct || tag (CtBlob).
pub const NET_UPSPA_GET_CSP_RESP_BYTES: usize =
    crypto::NONCE_LEN + upspa_proto::CIPHERSP_PT_LEN + crypto::TAG_LEN;

/// UpSPA store ciphersp request: suid(32) || CtBlob.
pub const NET_UPSPA_PUT_CSP_REQ_BYTES: usize = 32 + NET_UPSPA_GET_CSP_RESP_BYTES;
/// 1-byte status response for put ciphersp.
pub const NET_UPSPA_PUT_CSP_RESP_BYTES: usize = 1;

/// UpSPA password update request total size (uid_hash + msg + sig).
/// msg layout: cipherid_blob || share || timestamp || idx
pub const NET_UPSPA_PWDUPD_REQ_BYTES: usize = 32
    + (crypto::NONCE_LEN
        + upspa_proto::CIPHERID_PT_LEN
        + crypto::TAG_LEN
        + 32
        + 8
        + 4)
    + 64;
/// 1-byte status response for password update.
pub const NET_UPSPA_PWDUPD_RESP_BYTES: usize = 1;

/// Minimal in-memory UpSPA storage provider used by benchmarks.
///
/// Note: this is a simple, not thread-safe model intended for testing and
/// benchmarking. It stores the provider's TOPRF share, a signing key used
/// for password-update verification, and an in-memory map of stored ciphertexts.
#[derive(Clone)]
pub struct UpSpaProvider {
    pub sp_id: u32,
    /// TOPRF share `k_i`.
    pub share: Scalar,
    /// Verifying key `σ` stored at the provider for password updates.
    pub sig_pk: VerifyingKey,
    /// Per-login-server records keyed by `SUid`.
    pub ciphersp_db: HashMap<[u8; 32], crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>>,
    /// Optional cached latest cipherid blob (not strictly required for the scheme,
    /// but convenient for benchmarking an "apply update" write path).
    pub last_cipherid: crypto::CtBlob<{ upspa_proto::CIPHERID_PT_LEN }>,
    /// Monotonic timestamp guard for password updates.
    pub last_pwdupd_ts: u64,
}
