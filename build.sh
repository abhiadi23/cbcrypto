#!/usr/bin/env sh
# Build + install cbcrypto into the current Python. Works on Linux, macOS and Termux.
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}

if [ -n "$TERMUX_VERSION" ] || [ -d /data/data/com.termux ]; then
  echo ">> Termux detected"
  pkg install -y rust clang python >/dev/null 2>&1 || true
  PYVER=$($PY -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
  # Android's linker needs libpython as a real dependency of the extension
  export RUSTFLAGS="$RUSTFLAGS -C link-arg=-L${PREFIX}/lib -C link-arg=-lpython${PYVER}"
  cargo build --release
  DEST=$($PY -c 'import sysconfig;print(sysconfig.get_paths()["purelib"])')
  cp target/release/libcbcrypto.so "$DEST/cbcrypto.so"
else
  $PY -m pip install --quiet maturin
  $PY -m maturin build --release -o dist
  $PY -m pip install --force-reinstall dist/cbcrypto-*.whl
fi
$PY -c "import cbcrypto; print('cbcrypto', cbcrypto.__version__, '|', cbcrypto.backend())"
