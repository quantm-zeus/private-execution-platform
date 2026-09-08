use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
        .join("../../proto")
        .canonicalize()?;
    let proto_file = proto_root.join("evergreen/opaque/v1/relay.proto");

    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_protos(&[proto_file], &[proto_root])?;
    Ok(())
}
