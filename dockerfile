
FROM rust:latest AS builder
WORKDIR /app

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release --bins

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/bench_upspa /usr/local/bin/bench_upspa
COPY --from=builder /app/target/release/bench_tspa  /usr/local/bin/bench_tspa
COPY --from=builder /app/target/release/bench_setup /usr/local/bin/bench_setup
#   docker run IMAGE            -> runs UpSPA (default)
#   docker run IMAGE tspa       -> runs TSPA
#   docker run IMAGE setup      -> runs setup
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'cmd="${1:-upspa}"' \
  'shift || true' \
  'case "$cmd" in' \
  '  upspa)  exec /usr/local/bin/bench_upspa "$@" ;;' \
  '  tspa)   exec /usr/local/bin/bench_tspa "$@" ;;' \
  '  setup)  exec /usr/local/bin/bench_setup "$@" ;;' \
  '  *)' \
  '    echo "Unknown benchmark: $cmd" >&2' \
  '    echo "Use one of: upspa | tspa | setup" >&2' \
  '    exit 2' \
  '  ;;' \
  'esac' \
  > /usr/local/bin/run-bench \
  && chmod +x /usr/local/bin/run-bench

WORKDIR /out


ENTRYPOINT ["/usr/local/bin/run-bench"]
CMD ["upspa"]
