#!/bin/sh
# Boots each Ubuntu mainline kernel in a virtme-ng guest and runs the Linux
# suites in it (see kernel-guest.sh). From the repository root:
#
#   .github/kernel-lane.sh v6.8=4 v7.1=9 ...
#
# Each argument is a kernel tag and the Landlock ABI its probe must report.
# Needs cargo, python3, virtme-ng and QEMU; uses KVM when /dev/kvm is
# writable and plain emulation otherwise. The test binaries are built here
# and run in the guest without cargo. As root, the suites run as
# $PROCAGE_LANE_USER.
set -eu

target=${CARGO_TARGET_DIR:-$PWD/target}
mkdir -p "$target"
lists="$target/kernel-lane"
rm -rf "$lists" && mkdir "$lists"

# Builds and writes "<package dir> <binary>" per test binary to $lists/$1.
build() {
    list=$1
    shift
    cargo test --no-run --locked --message-format=json-render-diagnostics "$@" |
        python3 -c '
import json, os, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(os.path.dirname(m["manifest_path"]), m["executable"])
' >"$lists/$list"
}
build facts -p procage-kernel-facts --test kernel_facts
build suites -p procage --lib --test spawn_linux --test escape_linux --test unsafe_confined \
    --test native --test exec --test receipts --test audit --test oracle --test pty
build reporting -p procage --test escape_linux
build async -p procage --features tokio,proxy --test escape_linux --test tokio --test proxy

accel=""
scale=1
if [ ! -w /dev/kvm ]; then
    # Plain emulation runs the suites many times slower.
    accel="--disable-kvm"
    scale=10
fi
user=""
if [ "$(id -u)" -eq 0 ]; then
    user="--user ${PROCAGE_LANE_USER:?as root, name the user to run as}"
    chown -R "$PROCAGE_LANE_USER" "$target"
    HOME=$(getent passwd "$PROCAGE_LANE_USER" | cut -d: -f6)
fi

failed=""
for k in "$@"; do
    tag=${k%=*}
    abi=${k#*=}
    echo "==> kernel $tag (Landlock ABI $abi)"
    # Kernels before 6.x leave Landlock out of the default LSM list (it is
    # built, not enabled); name it on every kernel. Unknown names are ignored.
    if ! vng -r "$tag" $accel $user --memory 4G --cpus 4 --rwdir "$target" \
        --append "lsm=landlock,lockdown,yama,integrity,apparmor,bpf" \
        -- "HOME=$HOME PROCAGE_TIME_SCALE=$scale PROCAGE_LANE_ABI=$abi PROCAGE_LANE_LISTS=$lists sh $PWD/.github/kernel-guest.sh"; then
        failed="$failed $tag"
    fi
done
if [ -n "$failed" ]; then
    echo "failed kernels:$failed" >&2
    exit 1
fi
