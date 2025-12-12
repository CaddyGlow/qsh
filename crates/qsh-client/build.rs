fn main() {
    prost_build::compile_protos(&["src/control/control.proto"], &["src/control/"])
        .unwrap();
}
