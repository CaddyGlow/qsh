fn main() {
    prost_build::compile_protos(&["src/control.proto"], &["src/"]).unwrap();
}
