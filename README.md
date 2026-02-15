

# UpSpa VS TSPA Benchmark 

This repository contains a small **Rust** crate (`tspa`) together with **manual, reproducible micro-benchmarks** for evaluating **user-side costs** of threshold password authentication schemes.

Benchmarks are implemented on these parameters:

* fixed warmup + sample counts,
* deterministic RNG seeding,
* explicit CLI parameters,


---

## What is benchmarked

### UpSPA

User-side costs for:

* registration
* authentication
* secret update
* password update

### TSPA

User-side costs for:

* registration
* authentication (client prepare + finish only)

### Setup

User-side setup / key-generation cost.

All benchmarks measure **local computation only** (no networking).

---
### Implementation primitives

* Group: `ristretto255` instantiated via Curve25519 (Ristretto)
* Hash function: `BLAKE3`

For **TSPA**, we instantiate a non-threshold OPRF over `ristretto255` and protect stored client state and per-server records using **AES-256 in CTR mode**.

For **UpSPA**, we instantiate a threshold OPRF over `ristretto255` and protect client state and per-server records using **XChaCha20-Poly1305** authenticated encryption. Authenticated updates during password changes use **Ed25519** digital signatures.

You’re mixing **two different README versions**:

* Your README text assumes **3 binaries** (`bench_upspa`, `bench_tspa`, `bench_setup`) and `--out-prefix`.
* Your actual code you pasted earlier is a **single unified binary** (`bench_all.rs`) that uses `--scheme ... --out ...` (and optionally `--rng` / `--profile`).

So the README must be updated to match **bench_all.rs**. Below is a clean, paste-ready update that keeps your style, adds the formulas section, and fixes the “run locally / Docker” sections.

Copy-paste this block to replace your README from Repository layout down to the end.


## Repository layout

```
UpSpa_benchmark/
├── Cargo.toml
├── README.md
├── Dockerfile.yml
└── src/
├── lib.rs
├── crypto.rs
├── protocols/
│   ├── upspa.rs
│   └── tspa.rs
└── bin/
└── bench_all.rs

```

`src/bin/bench_all.rs` is a **single CLI benchmark binary** that can run **UpSPA**, **TSPA**, or **both**, and writes a single output `.dat` file.

---

## Output files

`bench_all` writes **one** `.dat` file (default: `unified_bench.dat`, or whatever you set via `--out`).

The output is plain text with whitespace-separated columns:

```

scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns

````

All times are reported in **nanoseconds**.

- `scheme ∈ {upspa, tspa}`
- `kind ∈ {proto, prim, bucket}` (bucket rows exist only if `--profile` is enabled)
- `op` is the operation name (e.g., `reg`, `auth`, `TOPRF_recv_eval_tsp`, `OPRF_recv_eval_tsp`, ...)

---

## Exact cost formulas (client-side)

This section summarizes the **client-side computation** that each benchmarked phase performs, expressed as a **count of primitive operations**.

Notation:

- `n = nsp` (number of storage providers)
- `t = tsp` (threshold)
- `H_*` = one BLAKE3-based hash invocation of the indicated kind
- `AEAD_DEC_cid` = XChaCha20-Poly1305 decrypt of `cipherid` (96B)
- `AEAD_ENC_sp` / `AEAD_DEC_sp` = XChaCha20-Poly1305 encrypt/decrypt of a `ciphersp` (40B)
- `AES_XOR_32` = AES-256-CTR XOR on 32 bytes
- `MulP` = Ristretto point-scalar multiplication
- `InvS` = scalar inversion
- `PolyEval(t-1)` = Shamir polynomial evaluation of degree `t-1` (Horner)
- `FieldMulAdd` = scalar ops used in interpolation (`acc += share * lambda`)


---

## Running locally (no Docker)

### Requirements

* Rust toolchain (edition 2021)
* Install via `rustup`

### Build

```bash
cargo build --release
````

---

## CLI usage (important)

`bench_all` supports the following flags:

| Flag             | Meaning                                   |
| ---------------- | ----------------------------------------- |
| `--scheme`       | `all` | `upspa` | `tspa`                  |
| `--nsp`          | Comma-separated list of number of servers |
| `--tsp`          | Absolute threshold list                   |
| `--tsp-pct`      | Threshold as percentage of `nsp`          |
| `--sample-size`  | Number of measured samples                |
| `--warmup-iters` | Warmup iterations                         |
| `--out`          | Output `.dat` path                        |
| `--rng-in-timed` | Include RNG in timed region (optional)    |
| `--profile`      | Emit extra `kind=bucket` rows (optional)  |
| `--bench`        | Ignored (Cargo/Windows noise)             |

You must choose **either** `--tsp` **or** `--tsp-pct`.

---

### Run both schemes (UpSPA + TSPA)

```bash
cargo run --release --bin bench_all -- \
  --scheme all \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-iters 300 \
  --sample-size 2000 \
  --out unified_bench.dat
```

### Run only UpSPA

```bash
cargo run --release --bin bench_all -- \
  --scheme upspa \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-iters 300 \
  --sample-size 2000 \
  --out upspa_only.dat
```

### Run only TSPA

```bash
cargo run --release --bin bench_all -- \
  --scheme tspa \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-iters 300 \
  --sample-size 2000 \
  --out tspa_only.dat
```

### Optional: enable bucket profiling

```bash
cargo run --release --bin bench_all -- \
  --scheme all \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-iters 300 \
  --sample-size 2000 \
  --profile \
  --out unified_bench_profiled.dat
```

---

## Running with Docker

Docker builds the benchmarks once and runs them inside a clean environment.

### Build the image

Your repo uses `Dockerfile.yml`, so build with `-f`:

```bash
docker build -f Dockerfile.yml -t upspa-benchmark .
```

### Run bench_all inside Docker

```bash
mkdir -p out

docker run --rm \
  -v "$(pwd)/out:/out" \
  upspa-benchmark \
  cargo run --release --bin bench_all -- \
    --scheme all \
    --nsp 20,40,60,80,100 \
    --tsp-pct 20,40,60,80,100 \
    --warmup-iters 300 \
    --sample-size 2000 \
    --out /out/unified_bench.dat
```

Results are written to `./out/unified_bench.dat`.

### Run with profiling inside Docker (optional)

```bash
mkdir -p out

docker run --rm \
  -v "$(pwd)/out:/out" \
  upspa-benchmark \
  cargo run --release --bin bench_all -- \
    --scheme all \
    --nsp 20,40,60,80,100 \
    --tsp-pct 20,40,60,80,100 \
    --warmup-iters 300 \
    --sample-size 2000 \
    --profile \
    --out /out/unified_bench_profiled.dat
```

---





