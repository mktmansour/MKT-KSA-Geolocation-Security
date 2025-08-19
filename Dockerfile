FROM rust:1.80-slim as builder

WORKDIR /app

# Pre-fetch dependencies for better caching
COPY Cargo.toml .
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN rustup component add clippy rustfmt && cargo fetch

# Copy full source
COPY . .

# Default command: run clippy strictly
CMD ["bash", "-lc", "cargo clippy --all-targets --all-features -- -W clippy::all -W clippy::pedantic -W clippy::cargo -W clippy::nursery -D warnings"]

