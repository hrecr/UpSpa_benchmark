use blake3;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::io::Read;


fn h32(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label);
    for p in parts {
        hasher.update(p);
    }
    let out = hasher.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn blake3_xof_64(h: blake3::Hasher) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut reader = h.finalize_xof();
    reader.read_exact(&mut out).expect("blake3 xof read failed");
    out
}

fn scalar_random(rng: &mut impl RngCore) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}


pub fn stor_uid(user_id: &[u8], ls_domain: &[u8]) -> [u8; 32] {
    h32(b"tspa:storuid:v1", &[user_id, ls_domain])
}

pub fn vinfo(rnd_bytes: &[u8], ls_domain: &[u8]) -> [u8; 32] {
    h32(b"tspa:vinfo:v1", &[rnd_bytes, ls_domain])
}


fn hash_to_point(pwd: &[u8]) -> RistrettoPoint {
    let mut h = blake3::Hasher::new();
    h.update(b"tspa:hash2point:v1");
    h.update(pwd);
    let wide = blake3_xof_64(h);
    RistrettoPoint::from_uniform_bytes(&wide)
}

#[derive(Clone)]
pub struct OprfRequest {
    pub blinded: RistrettoPoint,
    pub blind_inv: Scalar,
}

fn oprf_receiver_prepare(pwd: &[u8], rng: &mut impl RngCore) -> OprfRequest {
    let p = hash_to_point(pwd);
    let r = scalar_random(rng);
    let blinded = p * r;
    let blind_inv = r.invert();
    OprfRequest { blinded, blind_inv }
}

fn oprf_sender_eval(k_i: &Scalar, blinded: &RistrettoPoint) -> RistrettoPoint {
    blinded * k_i
}

fn oprf_receiver_finish(req: &OprfRequest, evaluated: &RistrettoPoint) -> [u8; 32] {
    let y = evaluated * req.blind_inv; // = k_i * H(pwd)
    let y_bytes = y.compress().to_bytes();
    h32(b"tspa:oprf-out:v1", &[&y_bytes])
}


fn aead_encrypt_share(key32: &[u8; 32], nonce12: &[u8; 12], share_y: &Scalar) -> Vec<u8> {
    let aead = ChaCha20Poly1305::new(key32.into());
    let nonce = Nonce::from_slice(nonce12);
    let pt = share_y.to_bytes();
    let mut ct = aead.encrypt(nonce, pt.as_ref()).expect("encrypt failed");

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce12);
    out.append(&mut ct);
    out
}

fn aead_decrypt_share(key32: &[u8; 32], blob: &[u8]) -> Scalar {
    assert!(blob.len() >= 12, "ciphertext too short");
    let (nonce12, ct) = blob.split_at(12);
    let aead = ChaCha20Poly1305::new(key32.into());
    let nonce = Nonce::from_slice(nonce12);
    let pt = aead.decrypt(nonce, ct).expect("decrypt failed");

    let mut b = [0u8; 32];
    b.copy_from_slice(&pt[..32]);
    Scalar::from_bytes_mod_order(b)
}


#[derive(Clone)]
struct Share {
    x: Scalar,
    y: Scalar,
}

fn poly_eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut pow = Scalar::ONE;
    for c in coeffs {
        acc += c * pow;
        pow *= x;
    }
    acc
}

fn shamir_reconstruct_zero(shares: &[Share]) -> Scalar {
    let mut secret = Scalar::ZERO;

    for i in 0..shares.len() {
        let xi = shares[i].x;
        let yi = shares[i].y;

        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;

        for j in 0..shares.len() {
            if i == j {
                continue;
            }
            let xj = shares[j].x;
            num *= xj;
            den *= xj - xi;
        }

        let li0 = num * den.invert();
        secret += yi * li0;
    }

    secret
}


#[derive(Clone)]
pub struct SpRecord {
    pub x: u16,
    pub k_i: Scalar,
    pub c_i: Vec<u8>,
}


#[derive(Clone)]
pub struct IterData {
    pub sp_indices: Vec<usize>, 
    pub iter_seed: [u8; 32],    
}

#[derive(Clone)]
pub struct SpAuthResponse {
    pub x: u16,
    pub evaluated: RistrettoPoint,
    pub c_i: Vec<u8>,
}



fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&nsp.to_le_bytes());
    h.update(&tsp.to_le_bytes());
    let out = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(out.as_bytes());
    s
}

pub fn make_iter_data(fx: &Fixture, rng: &mut impl RngCore) -> IterData {
    let mut sp_indices = Vec::with_capacity(fx.tsp);
    for i in 0..fx.tsp {
        sp_indices.push(i);
    }

    let mut iter_seed = [0u8; 32];
    rng.fill_bytes(&mut iter_seed);

    IterData { sp_indices, iter_seed }
}


pub fn auth_sp_process(fx: &Fixture, sp_index: usize, req: &OprfRequest) -> SpAuthResponse {
    let sp = &fx.sp_db[sp_index];
    let evaluated = oprf_sender_eval(&sp.k_i, &req.blinded);
    SpAuthResponse { x: sp.x, evaluated, c_i: sp.c_i.clone() }
}

pub fn auth_client_finish(fx: &Fixture, reqs: &[OprfRequest], resps: &[SpAuthResponse]) -> [u8; 32] {
    assert_eq!(reqs.len(), resps.len());

    let mut shares = Vec::with_capacity(reqs.len());
    for i in 0..reqs.len() {
        let key32 = oprf_receiver_finish(&reqs[i], &resps[i].evaluated);
        let y = aead_decrypt_share(&key32, &resps[i].c_i);
        let x = Scalar::from(resps[i].x as u64);
        shares.push(Share { x, y });
    }

    let rnd = shamir_reconstruct_zero(&shares);
    vinfo(&rnd.to_bytes(), &fx.ls_domain)
}


pub fn authentication_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_seed(seed_for(b"tspa:auth-client-rng:v3", fx.nsp, fx.tsp));
    let (_uid, reqs) = auth_client_prepare(fx, it, &mut rng);

    let mut resps = Vec::with_capacity(reqs.len());
    for (j, sp_index) in it.sp_indices.iter().enumerate() {
        resps.push(auth_sp_process(fx, *sp_index, &reqs[j]));
    }

    auth_client_finish(fx, &reqs, &resps)
}

fn oprf_key_direct_from_k(pwd_point: &RistrettoPoint, k_i: &Scalar) -> [u8; 32] {
    let y = pwd_point * k_i;
    let y_bytes = y.compress().to_bytes();
    h32(b"tspa:oprf-out:v1", &[&y_bytes])
}

fn oprf_receiver_prepare_from_point(pwd_point: &RistrettoPoint, rng: &mut impl RngCore) -> OprfRequest {
    let r = scalar_random(rng);
    let blinded = pwd_point * r;
    let blind_inv = r.invert();
    OprfRequest { blinded, blind_inv }
}


#[derive(Clone)]
pub struct Fixture {
    pub nsp: usize,
    pub tsp: usize,
    pub user_id: Vec<u8>,
    pub ls_domain: Vec<u8>,
    pub password: Vec<u8>,
    pub pwd_point: RistrettoPoint, 
    pub sp_db: Vec<SpRecord>,
}

pub fn make_fixture(nsp: usize, tsp: usize) -> Fixture {
    let mut rng = ChaCha20Rng::from_seed(seed_for(b"tspa:fixture:v4", nsp, tsp));

    let user_id = b"alice".to_vec();
    let ls_domain = b"example.com".to_vec();
    let password = b"correct horse battery staple".to_vec();
    let pwd_point = hash_to_point(&password);
    let rnd = scalar_random(&mut rng);

    let mut coeffs = Vec::with_capacity(tsp);
    coeffs.push(rnd);
    for _ in 1..tsp {
        coeffs.push(scalar_random(&mut rng));
    }

    let mut sp_db = Vec::with_capacity(nsp);
    for i in 0..nsp {
        let x_u16 = (i as u16) + 1;
        let x = Scalar::from(x_u16 as u64);
        let y = poly_eval(&coeffs, x);
        let k_i = scalar_random(&mut rng);
        let key32 = oprf_key_direct_from_k(&pwd_point, &k_i);
        let mut nonce12 = [0u8; 12];
        rng.fill_bytes(&mut nonce12);
        let c_i = aead_encrypt_share(&key32, &nonce12, &y);
        sp_db.push(SpRecord { x: x_u16, k_i, c_i });
    }

    Fixture { nsp, tsp, user_id, ls_domain, password, pwd_point, sp_db }
}

pub fn registration_user_side(fx: &Fixture, it: &IterData) -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_seed(it.iter_seed);
    let _uid = stor_uid(&fx.user_id, &fx.ls_domain);
    let rnd = scalar_random(&mut rng);
    let mut coeffs = Vec::with_capacity(fx.tsp);
    coeffs.push(rnd);
    for _ in 1..fx.tsp {
        coeffs.push(scalar_random(&mut rng));
    }
    let mut acc = blake3::Hasher::new();
    acc.update(b"tspa:reg:acc:v2");
    for i in 0..fx.nsp {
        let sp = &fx.sp_db[i];
        let x = Scalar::from(sp.x as u64);
        let share_y = poly_eval(&coeffs, x);
        let key32 = oprf_key_direct_from_k(&fx.pwd_point, &sp.k_i);
        let mut nonce12 = [0u8; 12];
        rng.fill_bytes(&mut nonce12);
        let c_i = aead_encrypt_share(&key32, &nonce12, &share_y);
        acc.update(&c_i);
    }

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}
pub fn auth_client_prepare(
    fx: &Fixture,
    it: &IterData,
    rng: &mut impl RngCore,
) -> ([u8; 32], Vec<OprfRequest>) {
    let uid = stor_uid(&fx.user_id, &fx.ls_domain);

    let mut reqs = Vec::with_capacity(it.sp_indices.len());
    for _ in 0..it.sp_indices.len() {
        reqs.push(oprf_receiver_prepare_from_point(&fx.pwd_point, rng));
    }

    (uid, reqs)
}
