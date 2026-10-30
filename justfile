# procage — development task runner (https://just.systems). `just ci` mirrors CI.
#
# The kernel facts verify enforcement on the running kernel. They fail (never
# skip) when run inside another Seatbelt sandbox, such as an agent harness:
# run them from a plain terminal (`just test-outside`).

msrv := "1.99.0"
rust_image := "rust:1.99"

default:
    @just --list --unsorted

# Every local quality gate, in order; stops at the first failure.
ci: fmt-check lint test doc package-docs deny msrv no-std semver planning-paths

# `ci` plus the Linux facts in containers and the macOS facts under Rosetta.
ci-all: ci kf-linux kf-linux-t1 kf-rosetta

fmt:
    cargo fmt --all

fmt-check:
    @echo "==> gate: fmt-check"
    cargo fmt --all --check

lint:
    @echo "==> gate: lint"
    cargo clippy --workspace --all-targets -- -D warnings

# Unit tests, doc tests and the kernel facts.
test:
    @echo "==> gate: test"
    cargo test --workspace
    cargo test -p procage-policy --all-features

# The kernel facts only; pass an id prefix to filter, e.g. `just facts KF-M1`.
facts *FILTER:
    cargo test -p procage-kernel-facts --test kernel_facts -- {{FILTER}}

# The kernel facts, with a reminder of where they must run.
test-outside:
    @echo "Run this from a terminal that is not inside an agent sandbox (Claude Code, Codex, sandbox-exec):"
    @echo "the report header must say 'sandboxed: no', or every enforcement fact fails."
    just facts

# Runs one fuzz target of the policy crate (nightly toolchain, cargo-fuzz).
fuzz target="quote" secs="60":
    cd crates/procage-policy && cargo +nightly fuzz run {{target}} -- -max_total_time={{secs}}

# Runs every fuzz target of the policy crate.
fuzz-all secs="60":
    just fuzz quote {{secs}}
    just fuzz glob {{secs}}
    just fuzz format {{secs}}
    just fuzz lower {{secs}}

# Bisects the rule count where libsandbox starts to abort (slow, opt-in).
bisect:
    PROCAGE_KF_BISECT=1 just facts KF-M24

doc:
    @echo "==> gate: doc"
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# The published packages (procage and its companion procage-policy) contain the
# threat model, and the docs build from the packages alone (outside the workspace).
package-docs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: package-docs"
    cargo package -p procage --allow-dirty --list | grep -qx THREAT_MODEL.md \
        || { echo "THREAT_MODEL.md is not in the package" >&2; exit 1; }
    cargo package -p procage -p procage-policy --allow-dirty --no-verify --quiet
    version=$(cargo pkgid -p procage | sed 's/.*[#@]//')
    policy=$(cargo pkgid -p procage-policy | sed 's/.*[#@]//')
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    tar -xzf "target/package/procage-$version.crate" -C "$dir"
    tar -xzf "target/package/procage-policy-$policy.crate" -C "$dir"
    (cd "$dir/procage-$version" && RUSTDOCFLAGS="-D warnings" CARGO_TARGET_DIR="$dir/target" \
        cargo doc --no-deps --quiet --config "patch.crates-io.procage-policy.path=\"$dir/procage-policy-$policy\"")
    test -f "$dir/target/doc/procage/threat_model/index.html"
    if [[ "$(uname -s)" == Darwin ]]; then test -f "$dir/target/doc/procage/macos/index.html"; fi

deny:
    @echo "==> gate: deny"
    cargo deny --workspace check

msrv:
    @echo "==> gate: msrv"
    cargo +{{msrv}} check --workspace --all-targets

# The policy crate must build without std (bare-metal target), with and
# without its data format.
no-std:
    @echo "==> gate: no-std"
    cargo build -p procage-policy --target thumbv7em-none-eabihf
    cargo build -p procage-policy --target thumbv7em-none-eabihf --features serde

semver:
    @echo "==> gate: semver"
    cargo semver-checks -p procage

# The published tree never cites the local planning directories.
planning-paths:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: planning-paths"
    paths=(src crates tests README.md THREAT_MODEL.md SECURITY.md Cargo.toml justfile deny.toml)
    [[ -d .github ]] && paths+=(.github)
    if grep -rnE '(concepts|specs|\.specify)/' "${paths[@]}"; then
        echo "planning paths found in the published tree" >&2
        exit 1
    fi

# Linux facts in a container under Docker's default seccomp profile (tier T2).
kf-linux tier="T2":
    @echo "==> gate: kf-linux ({{tier}})"
    docker run --rm --user 65534:65534 \
        -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target \
        -e PROCAGE_KF_EXPECT_TIER={{tier}} \
        -v "$PWD":/src:ro -w /src {{rust_image}} \
        cargo test --locked -p procage-kernel-facts --test kernel_facts

# Linux facts with seccomp and AppArmor unconfined, so user namespaces work (tier T1).
kf-linux-t1 tier="T1":
    @echo "==> gate: kf-linux-t1 ({{tier}})"
    docker run --rm --user 65534:65534 \
        --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
        -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target \
        -e PROCAGE_KF_EXPECT_TIER={{tier}} \
        -v "$PWD":/src:ro -w /src {{rust_image}} \
        cargo test --locked -p procage-kernel-facts --test kernel_facts

# macOS facts as x86_64 under Rosetta.
kf-rosetta:
    @echo "==> gate: kf-rosetta"
    cargo test -p procage-kernel-facts --test kernel_facts --target x86_64-apple-darwin
