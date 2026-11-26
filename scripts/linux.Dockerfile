# Toolchain image for scripts/linux.sh. The repo isn't copied in; it's mounted
# at run time. Keep the Rust version in step with RUST_VERSION in CI.
FROM rust:1.100.0-trixie
RUN rustup component add clippy rustfmt
# Not root, so permission failures behave as they do for a normal user. New
# volumes mounted on these directories inherit their ownership.
RUN useradd --create-home dev \
    && mkdir -p /target /scratch /usr/local/cargo/registry \
    && chown dev:dev /target /scratch /usr/local/cargo/registry
USER dev
ENV CARGO_TARGET_DIR=/target \
    PATH=/target/release:/usr/local/cargo/bin:$PATH
WORKDIR /src
