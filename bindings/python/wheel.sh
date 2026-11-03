#!/bin/sh
# The Python wheel as the release builds it, and its tests.
#
#   wheel.sh build OUT   builds the wheel into OUT (Linux: manylinux_2_28
#                        with zig; macOS: the host's arm64 wheel)
#   wheel.sh test DIR    installs the wheel from DIR in a fresh virtual
#                        environment and runs the tests and the example
#   wheel.sh all         both, in a temporary directory
#
# Build tools come from pinned PyPI versions in a virtual environment of
# their own.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
MATURIN="maturin==1.16.0"
ZIG="ziglang==0.17.0"

build() {
    out=$1
    tools=$(mktemp -d)
    python3 -m venv "$tools"
    if [ "$(uname)" = Linux ]; then
        "$tools/bin/pip" install -q "$MATURIN" "$ZIG"
        set -- --zig --compatibility manylinux_2_28
    else
        "$tools/bin/pip" install -q "$MATURIN"
        set --
    fi
    # maturin looks for zig through the tools' Python on PATH.
    (cd "$here" && PATH="$tools/bin:$PATH" maturin build --release --strip --out "$out" "$@")
}

check() {
    wheels=$1
    env=$(mktemp -d)
    python3 -m venv "$env"
    "$env/bin/pip" install -q --no-index "$wheels"/procage-*.whl
    cd "$here" && "$env/bin/python" -m unittest discover -s tests -v
}

case "${1:-all}" in
    build) build "$2" ;;
    test) check "$2" ;;
    all)
        out=$(mktemp -d)
        build "$out"
        check "$out"
        ;;
    *) echo "usage: wheel.sh build OUT | test DIR | all" >&2; exit 2 ;;
esac
