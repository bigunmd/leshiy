# Build stage: musl static binary via cargo-zigbuild.
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-pip nasm cmake && rm -rf /var/lib/apt/lists/*
RUN pip install --break-system-packages ziglang && \
    cargo install --locked cargo-zigbuild && \
    rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY . .
RUN cargo zigbuild --release --target x86_64-unknown-linux-musl -p leshiy && \
    cp target/x86_64-unknown-linux-musl/release/leshiy /leshiy

# Runtime stage: static binary on distroless static (no libc needed).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /leshiy /usr/local/bin/leshiy
USER nonroot
ENTRYPOINT ["/usr/local/bin/leshiy"]
