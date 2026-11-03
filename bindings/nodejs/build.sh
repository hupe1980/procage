#!/bin/sh
# The npm package as the release builds it, and its tests.
#
#   build.sh build [DIR]  compiles the addon for this host into
#                       DIR/procage.<platform>.node (DIR: this directory;
#                       Linux: glibc 2.28 with zig)
#   build.sh pack OUT   packs the package into OUT and checks its contents
#   build.sh test TGZ   installs the tarball into a scratch project and runs
#                       the tests and the example against it
#   build.sh all        all three, in a temporary directory
#
# Build tools come from pinned PyPI versions in a virtual environment of
# their own, as for the Python wheels.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ZIGBUILD="cargo-zigbuild==0.24.0"
ZIG="ziglang==0.17.0"

tag() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) echo darwin-arm64 ;;
        Linux-x86_64) echo linux-x64-gnu ;;
        Linux-aarch64) echo linux-arm64-gnu ;;
        *) echo "unsupported host $(uname -s)-$(uname -m)" >&2; exit 2 ;;
    esac
}

build() {
    target_dir=${CARGO_TARGET_DIR:-$root/target}
    if [ "$(uname -s)" = Linux ]; then
        tools=$(mktemp -d)
        python3 -m venv "$tools"
        "$tools/bin/pip" install -q "$ZIGBUILD" "$ZIG"
        triple="$(uname -m)-unknown-linux-gnu"
        (cd "$root" && PATH="$tools/bin:$PATH" cargo zigbuild --locked --release -p procage-node --target "$triple.2.28")
        lib="$target_dir/$triple/release/libprocage_node.so"
    else
        (cd "$root" && cargo build --locked --release -p procage-node)
        lib="$target_dir/release/libprocage_node.dylib"
    fi
    cp "$lib" "${1:-$here}/procage.$(tag).node"
    echo "built procage.$(tag).node"
}

# The tarball holds the module, its declarations, the addons, the README
# and the licences; anything else fails.
pack() {
    out=$1
    mkdir -p "$out"
    (cd "$here" && npm pack --silent --pack-destination "$out" >/dev/null)
    tgz=$(ls "$out"/procage-*.tgz)
    tar tzf "$tgz" | sort | node -e '
        const files = require("fs").readFileSync(0, "utf8").trim().split("\n").map((f) => f.replace(/^package\//, ""));
        const fixed = ["LICENSE-APACHE", "LICENSE-MIT", "README.md", "index.d.ts", "index.js", "package.json"];
        const addons = files.filter((f) => /^procage\.[a-z0-9-]+\.node$/.test(f));
        const other = files.filter((f) => !fixed.includes(f) && !addons.includes(f));
        if (other.length || !addons.length || fixed.some((f) => !files.includes(f))) {
            console.error("unexpected package contents:", files); process.exit(1);
        }
        console.log("package:", files.join(", "));'
}

check() {
    tgz=$1
    project=$(mktemp -d)
    (cd "$project" && npm init -y >/dev/null && npm pkg set type=module && npm install --silent --no-audit --no-fund "$tgz")
    cp -R "$here/test" "$here/examples" "$project/"
    (cd "$project" && node --test test/*.test.js)
}

case "${1:-all}" in
    build) build "${2:-}" ;;
    pack) pack "$2" ;;
    test) check "$2" ;;
    all)
        out=$(mktemp -d)
        build
        pack "$out"
        check "$(ls "$out"/procage-*.tgz)"
        ;;
    *) echo "usage: build.sh build | pack OUT | test TGZ | all" >&2; exit 2 ;;
esac
