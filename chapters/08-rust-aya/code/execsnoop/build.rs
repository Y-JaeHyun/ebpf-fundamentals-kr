// execsnoop-ebpf 크레이트를 BPF 타깃(bpfel-unknown-none)으로 빌드해 OUT_DIR에 둔다.
// aya-template의 build.rs와 같고, nightly 버전만 AYA_NIGHTLY 환경 변수로 고정할 수 있게 했다.
use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "execsnoop-ebpf")
        .ok_or_else(|| anyhow!("execsnoop-ebpf package not found"))?;
    let cargo_metadata::Package { name, manifest_path, .. } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    println!("cargo:rerun-if-env-changed=AYA_NIGHTLY");
    let nightly = std::env::var("AYA_NIGHTLY").ok();
    let toolchain = match nightly.as_deref() {
        Some(t) => Toolchain::Custom(t),
        None => Toolchain::Nightly,
    };
    aya_build::build_ebpf([ebpf_package], toolchain)
}
