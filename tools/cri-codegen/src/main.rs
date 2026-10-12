fn main() -> anyhow::Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = root.join("src/nodeguard/generated");
    std::fs::create_dir_all(&output)?;
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .out_dir(output)
        .build_client(true)
        .build_server(true)
        .compile_with_config(prost, &[root.join("vendor/cri/v0.36.4/api.proto")], &[root.join("vendor/cri/v0.36.4")])?;
    Ok(())
}
