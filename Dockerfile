FROM rust:slim-buster AS buildstage
WORKDIR /build
COPY . /build/
RUN rustup component add rustfmt
RUN cargo build --release --bin kms
FROM debian:buster-slim
COPY --from=buildstage /build/target/release/kms /usr/bin/
CMD ["kms"]
