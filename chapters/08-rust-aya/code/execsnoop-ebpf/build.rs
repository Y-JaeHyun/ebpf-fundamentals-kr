// bpf-linker가 바뀌면 다시 빌드하도록 알려 준다 (aya-template과 같다)
use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
