FROM rust:1.56.1 AS builder
RUN rustup component add rustfmt
WORKDIR /build
COPY . /build
RUN cargo build --release --bin kms
FROM debian:buster
RUN apt-get update && apt-get install -y libssl-dev
COPY --from=builder /build/target/release/kms /usr/bin/
CMD ["kms"]
