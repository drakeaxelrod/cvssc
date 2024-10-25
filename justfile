set windows-shell := ["powershell", "-Command"]


build:
  @echo "Building..."
  cargo build --release --target "wasm32-wasi"
  target\wasm32-wasi\release\cvssc.wasm
  ./wasi-stub.exe -r 0 "./target/wasm32-wasi/release/cvssc.wasm" -o "cvssc/cvssc.wasm"
  @echo "Done."