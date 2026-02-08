

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

---
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
        ├── bench_upspa.rs
        ├── bench_tspa.rs
        └── bench_setup.rs
```

Each file under `src/bin/` is a **standalone CLI benchmark binary**.

---

## Output files

Each benchmark writes one or more `.dat` files to disk.

### UpSPA

Produces:

* `upspa_reg.dat`
* `upspa_auth.dat`
* `upspa_secupd.dat`
* `upspa_pwdupd.dat`

### TSPA

Produces:

* `tspa_reg.dat`
* `tspa_auth.dat`

### Setup

Produces:

* `upspa_setup.dat`

All output files are plain text with whitespace-separated columns.

Typical header formats:

**UpSPA / TSPA**

```
nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns
```

**Setup**

```
nsp tsp_label t_abs samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns
```

All times are reported in **nanoseconds**.

---

## Running locally (no Docker)

### Requirements

* Rust toolchain (edition 2021)
* Install via `rustup`

### Build

```bash
cargo build --release
```

---

## CLI usage (important)

All benchmarks support the **same CLI interface**.

### Common flags

| Flag             | Meaning                                   |
| ---------------- | ----------------------------------------- |
| `--nsp`          | Comma-separated list of number of servers |
| `--tsp`          | Absolute threshold list                   |
| `--tsp-pct`      | Threshold as percentage of `nsp`          |
| `--sample-size`  | Number of measured samples                |
| `--warmup-iters` | Warmup iterations (UpSPA/TSPA)            |
| `--warmup-ms`    | Warmup time in ms (Setup only)            |
| `--out-prefix`   | Prefix for output files                   |
| `--bench`        | Ignored (Cargo/Windows noise)             |

You must choose **either** `--tsp` **or** `--tsp-pct`.

---

### UpSPA benchmark

```bash
cargo run --release --bin bench_upspa -- \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-iters 300 \
  --sample-size 2000 \
  --out-prefix upspa
```

Writes:

```
upspa_reg.dat
upspa_auth.dat
upspa_secupd.dat
upspa_pwdupd.dat
```

---

### TSPA benchmark

```bash
cargo run --release --bin bench_tspa -- \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-iters 300 \
  --sample-size 2000 \
  --out-prefix tspa
```

Writes:

```
tspa_reg.dat
tspa_auth.dat
```

---

### Setup benchmark

```bash
cargo run --release --bin bench_setup -- \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100 \
  --warmup-ms 2000 \
  --sample-size 100 \
  --out-prefix setup
```

Writes:

```
setup_upspa_setup.dat
```

---

## Running with Docker

Docker builds the binaries once and runs them in a clean, reproducible environment.

### Build image

```bash
docker build -t upspa-benchmark .
```

---

### Run UpSPA benchmark

```bash
mkdir -p out
docker run --rm \
  -v "$(pwd)/out:/out" \
  upspa-benchmark upspa \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100
```

Results appear in `./out/`.



### Run TSPA benchmark

```bash
mkdir -p out
docker run --rm \
  -v "$(pwd)/out:/out" \
  upspa-benchmark tspa \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100
```

---

### Run Setup benchmark

```bash
mkdir -p out
docker run --rm \
  -v "$(pwd)/out:/out" \
  upspa-benchmark setup \
  --nsp 20,40,60,80,100 \
  --tsp-pct 20,40,60,80,100
```

---







