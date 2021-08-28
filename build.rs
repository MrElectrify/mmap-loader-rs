use std::io::Result;

fn main() -> Result<()> {
    tonic_build::compile_protos("proto/mmap.proto")?;
    Ok(())
}
