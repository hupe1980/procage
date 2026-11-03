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
ci: fmt-check lint test doc package-docs deny msrv no-std features semver planning-paths workflows

# `ci` plus the Linux facts and tests in containers.
ci-all: ci kf-linux kf-linux-t1 linux linux-t1

fmt:
    cargo fmt --all

fmt-check:
    @echo "==> gate: fmt-check"
    cargo fmt --all --check

lint:
    @echo "==> gate: lint"
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo clippy --workspace --all-targets --all-features --target aarch64-unknown-linux-gnu -- -D warnings
    cargo clippy --workspace --all-targets --all-features --target x86_64-unknown-linux-musl -- -D warnings
    cargo clippy -p procage --all-targets -- -D warnings
    cargo clippy -p procage --all-targets --target aarch64-unknown-linux-gnu -- -D warnings
    # The fuzz targets are their own workspace; check that they still build.
    cargo check --manifest-path crates/procage-policy/fuzz/Cargo.toml --bins
    cargo check --manifest-path crates/procage-proxy/fuzz/Cargo.toml --bins

# Unit tests, doc tests and the kernel facts.
test:
    @echo "==> gate: test"
    cargo test --workspace
    cargo test -p procage-policy --all-features
    cargo test -p procage --features tokio,proxy --lib --test tokio --test proxy

# Spawn latency against a plain spawn and sandbox-exec or bwrap; run outside any sandbox.
bench *ARGS:
    cargo bench -p procage --bench spawn -- {{ARGS}}

# The kernel facts only; pass an id prefix to filter, e.g. `just facts KF-M1`.
facts *FILTER:
    cargo test -p procage-kernel-facts --test kernel_facts -- {{FILTER}}

# The kernel facts, with a reminder of where they must run.
test-outside:
    @echo "Run this from a terminal that is not inside an agent sandbox (Claude Code, Codex, sandbox-exec):"
    @echo "the report header must say 'sandboxed: no', or every enforcement fact fails."
    just facts

# Runs one fuzz target of the policy crate, or of `crate` (nightly
# toolchain, cargo-fuzz). The host target is explicit: a prebuilt cargo-fuzz
# defaults to its own (musl).
fuzz target="quote" secs="60" crate="procage-policy":
    cd crates/{{crate}} && cargo +nightly fuzz run --target "$(rustc +nightly -vV | sed -n 's/^host: //p')" {{target}} -- -max_total_time={{secs}}

# Runs every fuzz target.
fuzz-all secs="60":
    just fuzz quote {{secs}}
    just fuzz glob {{secs}}
    just fuzz format {{secs}}
    just fuzz lower {{secs}}
    just fuzz host {{secs}} procage-proxy

# Bisects the rule count where libsandbox starts to abort (slow, opt-in).
bisect:
    PROCAGE_KF_BISECT=1 just facts KF-M24

doc:
    @echo "==> gate: doc"
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --target aarch64-unknown-linux-gnu

# The published packages (procage and its companions procage-policy and
# procage-proxy) contain the threat model, and the docs build from the packages
# alone (outside the workspace), with every feature.
package-docs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: package-docs"
    cargo package -p procage --allow-dirty --list | grep -qx THREAT_MODEL.md \
        || { echo "THREAT_MODEL.md is not in the package" >&2; exit 1; }
    cargo package -p procage -p procage-policy -p procage-proxy --allow-dirty --no-verify --quiet
    version=$(cargo pkgid -p procage | sed 's/.*[#@]//')
    policy=$(cargo pkgid -p procage-policy | sed 's/.*[#@]//')
    proxy=$(cargo pkgid -p procage-proxy | sed 's/.*[#@]//')
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    tar -xzf "target/package/procage-$version.crate" -C "$dir"
    tar -xzf "target/package/procage-policy-$policy.crate" -C "$dir"
    tar -xzf "target/package/procage-proxy-$proxy.crate" -C "$dir"
    (cd "$dir/procage-$version" && RUSTDOCFLAGS="-D warnings" CARGO_TARGET_DIR="$dir/target" \
        cargo doc --no-deps --quiet --all-features \
        --config "patch.crates-io.procage-policy.path=\"$dir/procage-policy-$policy\"" \
        --config "patch.crates-io.procage-proxy.path=\"$dir/procage-proxy-$proxy\"")
    test -f "$dir/target/doc/procage/threat_model/index.html"
    if [[ "$(uname -s)" == Darwin ]]; then test -f "$dir/target/doc/procage/macos/index.html"; fi

deny:
    @echo "==> gate: deny"
    cargo deny --workspace check

msrv:
    @echo "==> gate: msrv"
    cargo +{{msrv}} check --workspace --all-targets --all-features

# The policy crate must build without std (bare-metal target), with and
# without its data format.
no-std:
    @echo "==> gate: no-std"
    cargo build -p procage-policy --target thumbv7em-none-eabihf
    cargo build -p procage-policy --target thumbv7em-none-eabihf --features serde

# Without features, procage depends on no async runtime and no proxy.
features:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: features"
    if cargo tree -p procage -e normal --target all --prefix none | grep -E '^(tokio|mio|futures[a-z-]*|procage-proxy) '; then
        echo "the default build depends on an optional crate" >&2; exit 1
    fi
    cargo tree -p procage -e normal --target all --prefix none --features tokio | grep -q '^tokio '

semver:
    @echo "==> gate: semver"
    cargo semver-checks -p procage

# The published tree never cites the local planning directories.
planning-paths:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: planning-paths"
    status=0
    # The crates never cite planning files.
    if grep -rnE '(concepts|specs|\.specify)/' crates Cargo.toml deny.toml; then
        echo "planning paths in the crates" >&2; status=1
    fi
    # README, SECURITY, the site and CI may link the design records, never private notes.
    others=(README.md SECURITY.md site justfile)
    [[ -d .github ]] && others+=(.github)
    if grep -rnE 'concepts[/]' "${others[@]}"; then
        echo "private notes cited in the published tree" >&2; status=1
    fi
    # The design records stand alone: no private note, consumer, local path or e-mail.
    records=(specs .specify/memory)
    pattern='concepts|D-[0-9]{3}|Q-[0-9]{2}\b|F-[0-9]{2}\b|research/0|[Rr]oadmap|speccoder|ordex|\bbilling\b|\bsepa\b|/Users/|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}'
    if [[ -d specs ]] && grep -rnE --exclude='incoming-*' "$pattern" "${records[@]}"; then
        echo "private references in the design records" >&2; status=1
    fi
    exit $status

# The workflows hold least privilege, and the README's lane table names
# exactly the runners CI uses.
workflows:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: workflows"
    status=0
    fail() { echo "$1" >&2; status=1; }
    wf=(.github/workflows/*.yml)
    # Every action at a full commit SHA, with its version as a comment.
    if grep -nE '^\s*(- )?uses:' "${wf[@]}" | grep -vE 'uses: (\./|[^@ ]+@[0-9a-f]{40} # v[0-9])'; then
        fail "actions not pinned to a full SHA with a version comment"
    fi
    for f in "${wf[@]}"; do
        grep -qxE 'permissions:' "$f" && grep -A1 -xE 'permissions:' "$f" | grep -qxE '  contents: read' \
            || fail "$f: no top-level read-only token"
    done
    if grep -nE 'pull_request_target|workflow_run' "${wf[@]}"; then fail "pull-request code under a privileged trigger"; fi
    # Pull-request and commit text reach scripts through env only.
    if grep -nE '\$\{\{ *github\.(event\.|head_ref)' "${wf[@]}"; then fail "untrusted context in an expression"; fi
    if grep -nE 'actions/cache|cache:|continue-on-error' "${wf[@]}"; then fail "a cache or a lane allowed to fail"; fi
    # The test lanes: no widened token, no secrets.
    if grep -nE '^ +permissions:|secrets\.' .github/workflows/ci.yml | grep -vE '^[0-9]+: *#'; then fail "ci.yml widens the token or uses secrets"; fi
    ci=$(grep -oE '(runs-on|os): *[a-z][a-z0-9.-]+' .github/workflows/ci.yml | sed 's/.*: *//' | sort -u || true)
    readme=$(grep -oE '^\| `[a-z][a-z0-9.-]+` \|' README.md | tr -d '|` ' | sort -u || true)
    if [[ "$ci" != "$readme" ]]; then
        diff <(echo "$ci") <(echo "$readme") | sed 's/^</  only in ci.yml:/; s/^>/  only in README:/' | grep only >&2 || true
        fail "the README's lane table and ci.yml name different runners"
    fi
    exit $status

# The landing page and documentation (Zola): link check and build.
site:
    @echo "==> gate: site"
    cd site && zola check && zola build

# The macOS escape suite: one or more canaries per escape class, without and
# with violation reporting (run outside any other sandbox).
escape:
    @echo "==> gate: escape (macOS)"
    cargo test --locked -p procage --test escape_macos --test spelling_macos
    PROCAGE_ESCAPE_VIOLATIONS=1 cargo test --locked -p procage --test escape_macos
    PROCAGE_ESCAPE_BASE=v3 PROCAGE_ESCAPE_VIOLATIONS=1 cargo test --locked -p procage --test escape_macos
    PROCAGE_ASYNC=1 cargo test --locked -p procage --features tokio,proxy --test escape_macos --test tokio --test proxy

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

kernels := "v5.15=1 v6.6=3 v6.8=4 v6.12=6 v7.0=8 v7.1=9 v7.2=10 v7.3.1=11"

# The Linux suites on real mainline kernels, each booted in a virtme-ng
# guest (QEMU without KVM inside the container: slow, but the same kernel).
# `just kernel v7.1=9` runs one; the default is the whole matrix.
kernel +kernels=kernels:
    @echo "==> gate: kernel ({{kernels}})"
    docker run --rm -v "$PWD":/src:ro -w /src {{rust_image}} sh -c '\
        set -e; apt-get update -qq >/dev/null; \
        apt-get install -y -qq qemu-system-arm qemu-system-x86 python3-venv busybox-static udev kmod file zstd iproute2 >/dev/null; \
        python3 -m venv /opt/vng && /opt/vng/bin/pip install -q virtme-ng==1.42; \
        [ "$(uname -m)" = x86_64 ] || rm -f /opt/vng/lib/python3*/site-packages/virtme/guest/bin/virtme-ng-init; \
        useradd -m -u 1000 -s /bin/sh lane; mkdir -p /work && chown lane /work; \
        export PATH=/opt/vng/bin:$PATH CARGO_TARGET_DIR=/work/target PROCAGE_LANE_USER=lane; \
        .github/kernel-lane.sh {{kernels}}'

# The Linux backend's tests in a container under Docker's default seccomp profile (tier T2).
linux tier="T2":
    @echo "==> gate: linux ({{tier}})"
    docker run --rm --user 65534:65534 \
        -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target \
        -e PROCAGE_EXPECT_TIER={{tier}} \
        -v "$PWD":/src:ro -w /src {{rust_image}} \
        sh -c 'cargo test --locked -p procage --lib --test spawn_linux --test escape_linux --test unsafe_confined --test native --test exec --test receipts --test audit --test oracle --test pty && PROCAGE_ESCAPE_VIOLATIONS=1 cargo test --locked -p procage --test escape_linux && PROCAGE_ASYNC=1 cargo test --locked -p procage --features tokio,proxy --test escape_linux --test tokio --test proxy'

# The Linux backend's tests with seccomp and AppArmor unconfined, so user namespaces work (tier T1).
linux-t1 tier="T1":
    @echo "==> gate: linux-t1 ({{tier}})"
    docker run --rm --user 65534:65534 \
        --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
        -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target \
        -e PROCAGE_EXPECT_TIER={{tier}} \
        -v "$PWD":/src:ro -w /src {{rust_image}} \
        sh -c 'cargo test --locked -p procage --lib --test spawn_linux --test escape_linux --test unsafe_confined --test native --test exec --test receipts --test audit --test oracle --test pty && PROCAGE_ESCAPE_VIOLATIONS=1 cargo test --locked -p procage --test escape_linux && PROCAGE_ASYNC=1 cargo test --locked -p procage --features tokio,proxy --test escape_linux --test tokio --test proxy'
