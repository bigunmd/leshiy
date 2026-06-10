# Build stage: cross-compile a static musl binary on the NATIVE builder arch (fast — avoids
# QEMU-emulating the whole compile), targeting the requested platform via cargo-zigbuild.
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-pip nasm cmake && rm -rf /var/lib/apt/lists/*
RUN pip install --break-system-packages ziglang && \
    cargo install --locked cargo-zigbuild
WORKDIR /src
COPY . .
# Map the buildx TARGETARCH to a musl triple, then add it to the toolchain rust-toolchain.toml
# selects (channel = "stable"). Adding it here in /src (NOT /) is what makes cargo-zigbuild
# find it; adding it earlier targets the image's default toolchain → "can't find crate for `core`".
RUN case "$TARGETARCH" in \
      amd64) TRIPLE=x86_64-unknown-linux-musl ;; \
      arm64) TRIPLE=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup target add "$TRIPLE" && \
    cargo zigbuild --release --target "$TRIPLE" -p leshiy && \
    cp "target/$TRIPLE/release/leshiy" /leshiy

# Runtime stage: static binary on distroless static (no libc needed).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /leshiy /usr/local/bin/leshiy
USER nonroot
ENTRYPOINT ["/usr/local/bin/leshiy"]
