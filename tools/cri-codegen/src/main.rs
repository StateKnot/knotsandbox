fn main() -> anyhow::Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = root.join("src/nodeguard/generated");
    std::fs::create_dir_all(&output)?;
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments == ["--containerd"] {
        // Generate messages only: the production adapter exposes fixed
        // read methods, rather than a generated client with write operations.
        prost.compile_well_known_types();
        tonic_prost_build::configure()
            .out_dir(output)
            .build_client(false)
            .build_server(false)
            .compile_with_config(
                prost,
                &[
                    root.join("vendor/containerd/v2.3.5/api/services/images/v1/images.proto"),
                    root.join("vendor/containerd/v2.3.5/api/services/content/v1/content.proto"),
                    root.join("vendor/containerd/v2.3.5/api/services/snapshots/v1/snapshots.proto"),
                ],
                &[
                    root.join("vendor/containerd/v2.3.5/api"),
                    root.join("vendor/protobuf/protoc-bin-vendored-3.2.0/include"),
                ],
            )?;
        return Ok(());
    }
    anyhow::ensure!(arguments.is_empty(), "unknown protocol generation mode");
    tonic_prost_build::configure()
        .out_dir(output)
        .build_client(true)
        .build_server(true)
        .compile_with_config(
            prost,
            &[root.join("vendor/cri/v0.36.4/api.proto")],
            &[root.join("vendor/cri/v0.36.4")],
        )?;
    Ok(())
}
