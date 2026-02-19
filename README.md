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