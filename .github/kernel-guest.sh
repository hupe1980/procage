#!/bin/sh
# Runs inside a kernel-lane guest: the kernel facts with the expected ABI,
# every Linux suite, the escape suite with violation reporting and through
# tokio. Each list names the test binaries kernel-lane.sh built. Every step
# runs; the exit status says whether any failed.
set -u
export PROCAGE_EXPECT_TIER=T1 PROCAGE_KF_EXPECT_TIER=T1 \
    PROCAGE_KF_EXPECT_ABI="$PROCAGE_LANE_ABI"
echo "kernel: $(uname -r), $(date -u +%Y-%m-%d)"
status=0
run() {
    while read -r dir exe; do
        echo "--- $(basename "$exe") ($1)"
        (cd "$dir" && env $2 "$exe" -q) || status=1
    done <"$PROCAGE_LANE_LISTS/$1"
}
run facts ""
run suites ""
run reporting PROCAGE_ESCAPE_VIOLATIONS=1
run async PROCAGE_ASYNC=1
exit $status
