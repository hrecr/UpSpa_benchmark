# UpSPA vs TSPA Benchmarks (Rust)

This repository contains a small Rust crate (`(Up/T)SPA`) plus a **single, unified benchmark binary** that can measure:

- **Client protocol phases** (`kind=proto`)
- **Client cryptographic primitives** (`kind=prim`)
- **Server/storage-provider primitives** (`kind=sp`)
- **Network-only simulation** for LAN/WAN (`kind=net`)
- **Modeled end-to-end totals** = client(measured) + network(simulated) + server(p50 injected) (`kind=full`)

The benchmark suite is **manual and reproducible**:
- fixed warmup + sample counts,
- deterministic seeding (BLAKE3 → ChaCha20Rng),
- explicit CLI flags,
- results written to a single whitespace-separated `.dat` file.


---

## Repository layout

```
UpSpa_benchmark/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs
    ├── crypto.rs
    ├── crypto_tspa.rs
    ├── protocols/
    │   ├── sp.rs
    │   ├── upspa.rs
    │   └── tspa.rs
    └── bin/
        └── bench_unified.rs
```

`src/bin/bench_unified.rs` is the **single** benchmark binary.

---

## Output format

`bench_unified` writes one output file (default: `unified_bench.dat`) with header:

```
scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns
```

- times are in **nanoseconds**
- fields are **whitespace-separated** (easy to parse as CSV by splitting on spaces)
- `scheme ∈ {upspa, tspa}`
- `kind ∈ {proto, prim, sp, net, full}`
- `op` identifies the measured operation (see lists below)

`rng_in_timed` is `1` if `--rng-in-timed` was passed, else `0`.

---

## What each benchmark kind measures

### `--kind proto` (client protocol phases)

Measures **client-side computation only** for protocol phases.

**UpSPA (`scheme=upspa`):**
- `setup`
- `reg`
- `auth` (uses the “2-decrypt” variant: decrypt `cipherid` once + decrypt **one** `ciphersp` once)
- `secupd`
- `pwdupd` (v1) and/or `pwdupd_v2` (v2), controlled by `--pwdupd`

**TSPA (`scheme=tspa`):**
- `setup` (client-side placeholder only; real server init is in `sp`/`full`)
- `reg`
- `auth`

### `--kind prim` (client cryptographic primitives)

Measures **microbenchmarks** of individual client primitives (hash, AEAD, (T)OPRF steps, etc.).
See “Primitive op names” below.

### `--kind sp` (server/storage-provider primitives)

Measures **server-side** primitive costs for a *single* provider instance (no networking):
- TOPRF/OPRF server evaluation
- DB get/put operations (modeled as provider map ops)
- password-update verification/apply (v1 and v2 separated)

See “Primitive op names” below.

### `--kind net` (network-only simulation)

Measures **simulated network time only** (LAN/WAN), with **server processing set to 0**.
This is useful to isolate communication overhead from computation.

Output ops look like:
- `lan_reg_net`, `wan_auth_net`, …

### `--kind full` (modeled end-to-end)

Measures a modeled end-to-end time per phase:

\$
T_{full} = T_{client,measured} + T_{net,simulated}(\text{LAN/WAN}, \text{bytes}, \text{jitter}, \text{bw}, \text{overhead}, proc_{p50})
\$

Where:
- `T_client,measured` is real local timing of the client phase implementation.
- `T_net,simulated` is the network simulator (same model as `bench_net.rs`).
- `proc_p50` is injected per-provider processing time, measured **on this machine** via server primitive microbench medians (p50).

Output ops look like:
- `lan_reg_total`, `wan_auth_total`, …

---

## Password update variants (UpSPA)

Select with `--pwdupd`:

- **v1** (`pwdupd`): re-key/update shares + **per-provider signature(s)** (heavier)
- **v2** (`pwdupd_v2`): keep existing TOPRF shares, re-encrypt `cipherid` under TOPRF(newpwd), **sign once** (lighter)

`--pwdupd both` outputs both v1 and v2 rows for pwdupd-related ops (proto/sp/net/full). Other phases are output once.


---