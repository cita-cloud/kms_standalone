fn main() -> Result<(), Box<dyn std::error::Error>> {
    // sqlx
    // trigger recompilation when a new migration is added
    println!("cargo:rerun-if-changed=migrations");

    println!("cargo:rerun-if-changed=proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .format(true)
        .compile(
            &["blockchain.proto", "common.proto", "kms.proto"],
            &["proto"],
        )?;
    Ok(())
}
