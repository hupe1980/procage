// The binding on the kernel: the escape subset and the API, run from the
// installed package with Node's own test runner (node --test).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Cage,
  CapabilityGapError,
  ExitError,
  GrantError,
  Policy,
  PolicyError,
  ProcageError,
  TimeoutError,
  run,
} from "procage";

const MACOS = process.platform === "darwin";

const workspace = () => realpathSync(mkdtempSync(join(tmpdir(), "procage-node-")));

/** A cage as a Linux user makes one (see the README). */
function cage(policy, options = {}) {
  const linux = MACOS ? {} : { acceptSpawnSnapshot: true, relax: ["waive:trust-handoff"] };
  return new Cage(policy, { ...linux, ...options });
}

const preset = (ws) => Policy.preset("agent_workspace", 3, { workspace: ws });

/**
 * `policy` that may also run this Node binary, wherever it is installed (a
 * version manager or CI's tool cache is outside every preset), as a user
 * whose tools run Node would write it.
 */
function withNode(policy) {
  const doc = policy.toJSON();
  doc.fs.push({ access: "exec", target: { subpath: dirname(realpathSync(process.execPath)) } });
  return Policy.fromJSON(doc);
}

function gone(pid, within = 5000) {
  const end = Date.now() + within;
  while (Date.now() < end) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    spawnSync("/bin/sleep", ["0.02"]);
  }
  return false;
}

describe("escape subset", () => {
  const ws = workspace();
  const outside = workspace();
  writeFileSync(join(outside, "f"), "outside");
  const c = cage(preset(ws));

  it("the workspace is usable, and is the working directory", async () => {
    const done = await run(c, "echo hi > f && cat f && pwd", { shell: true });
    assert.equal(done.exitCode, 0, done.stderr);
    assert.equal(done.stdout, `hi\n${ws}\n`);
  });

  it("reading outside the workspace is refused", async () => {
    const done = await run(c, ["/bin/cat", join(outside, "f")]);
    assert.notEqual(done.exitCode, 0);
    assert.doesNotMatch(done.stdout, /outside/);
  });

  it("writing outside the workspace is refused", async () => {
    const done = await run(c, `echo x > '${join(outside, "g")}'`, { shell: true });
    assert.notEqual(done.exitCode, 0);
    assert.equal(existsSync(join(outside, "g")), false);
  });

  it("a secret is refused", async () => {
    if (MACOS) {
      const keychains = join(homedir(), "Library/Keychains");
      assert.ok(existsSync(keychains));
      const done = await run(c, ["/bin/ls", keychains]);
      assert.notEqual(done.exitCode, 0);
      return;
    }
    const dir = join(homedir(), ".aws");
    mkdirSync(dir, { recursive: true });
    const secret = join(dir, `procage-canary-${process.pid}`);
    writeFileSync(secret, "key");
    try {
      const done = await run(c, ["/bin/cat", secret]);
      assert.notEqual(done.exitCode, 0);
      assert.doesNotMatch(done.stdout, /key/);
    } finally {
      rmSync(secret);
    }
  });

  it("the network is refused", async () => {
    const script = "require('net').connect(53, '1.1.1.1').on('connect', () => process.exit(0)).on('error', (e) => { console.error(e.code); process.exit(1) })";
    const done = await run(cage(withNode(preset(ws))), [process.execPath, "-e", script], { cwd: ws, timeout: 30_000 });
    assert.notEqual(done.exitCode, 0, done.stderr);
  });

  it("process.env is not copied", async () => {
    process.env.PROCAGE_NODE_SECRET = "s3cret";
    try {
      const done = await run(c, ["/usr/bin/env"], { env: { VISIBLE: 1 } });
      assert.equal(done.exitCode, 0, done.stderr);
      assert.doesNotMatch(done.stdout, /s3cret/);
      assert.match(done.stdout, /VISIBLE=1/);
    } finally {
      delete process.env.PROCAGE_NODE_SECRET;
    }
  });
});

describe("policies", () => {
  it("an unknown field is refused", () => {
    assert.throws(() => Policy.fromJSON({ version: 1, bogus: 1 }), PolicyError);
  });

  it("presets need a known name and an absolute workspace", () => {
    for (const [name, version, ws] of [["nope", 3, "/tmp"], ["agent_workspace", 9, "/tmp"], ["agent_workspace", 3, "rel"]]) {
      assert.throws(() => Policy.preset(name, version, { workspace: ws }), PolicyError);
    }
    assert.throws(() => Policy.preset("agent_workspace", 3), PolicyError);
  });

  it("JSON round-trips, and URLs are paths", () => {
    const ws = workspace();
    const p = Policy.preset("agent_readonly", 3, { workspace: new URL(`file://${ws}/`) });
    assert.equal(p.workspace, ws);
    assert.deepEqual(Policy.fromJSON(JSON.stringify(p)).toJSON(), p.toJSON());
  });

  it("a gap throws with the gaps", () => {
    let policy, construct;
    if (MACOS) {
      const doc = Policy.preset("minimal", 3).toJSON();
      doc.linux = { syscalls_deny: [], landlock_extra: [] };
      [policy, construct] = [Policy.fromJSON(doc), "linux-layer"];
    } else {
      [policy, construct] = [Policy.preset("build", 3, { workspace: workspace() }), "net-loopback"];
    }
    assert.throws(
      () => new Cage(policy, { acceptSpawnSnapshot: true }),
      (e) => e instanceof CapabilityGapError && e instanceof ProcageError && e.gaps.some((g) => g.construct === construct),
    );
  });

  it("a gap names the option that accepts it (Linux)", { skip: MACOS && "macOS enforces the workspace preset exactly" }, () => {
    assert.throws(
      () => new Cage(preset(workspace())),
      (e) => e instanceof CapabilityGapError && /accepts it/.test(e.message) && e.gaps.some((g) => g.accept.length),
    );
  });

  it("exec program runs the program only", async () => {
    // By the policy JSON; on Linux an approximation accepted by name,
    // which the gap spells out.
    const policy = Policy.fromJSON({ version: 1, base: "v1", process: { exec: "program", fork: true } });
    let c;
    if (MACOS) {
      c = new Cage(policy);
    } else {
      assert.throws(
        () => new Cage(policy, { acceptSpawnSnapshot: true }),
        (e) => e instanceof CapabilityGapError && e.gaps[0].accept.includes('allow: ["exec-program"]'),
      );
      c = new Cage(policy, { acceptSpawnSnapshot: true, allow: ["exec-program"] });
    }
    const done = await run(c, ["/bin/bash", "-c", "/bin/echo no 2>/dev/null || echo refused"]);
    assert.equal(done.stdout, "refused\n");
  });

  it("an allowed construct is checked", () => {
    assert.throws(() => new Cage(Policy.preset("minimal", 3), { allow: ["no-such-construct"] }), PolicyError);
  });

  it("a relaxation name is checked", () => {
    assert.throws(() => new Cage(Policy.preset("minimal", 3), { relax: ["waive:nope"] }), PolicyError);
  });
});

describe("like child_process", () => {
  const ws = workspace();
  const c = cage(preset(ws));

  it("input, buffers and the shell", async () => {
    assert.equal((await run(c, "echo $((6*7))", { shell: true })).stdout, "42\n");
    const done = await run(c, ["/bin/cat"], { input: "in", encoding: "buffer" });
    assert.deepEqual(done.stdout, Buffer.from("in"));
  });

  it("check rejects with ExitError and the result", async () => {
    await assert.rejects(run(c, "exit 7", { shell: true, check: true }), (e) => e instanceof ExitError && e.result.exitCode === 7);
  });

  it("the command and shell must agree", async () => {
    await assert.rejects(run(c, "echo hi"), TypeError);
    await assert.rejects(run(c, ["echo", "hi"], { shell: true }), TypeError);
  });
});

describe("lifetime", () => {
  const ws = workspace();
  const c = cage(preset(ws));

  it("a timeout ends the run", async () => {
    const pidFile = join(ws, "t.pid");
    await assert.rejects(run(c, `echo $$ > t.pid; exec sleep 300`, { shell: true, timeout: 500 }), TimeoutError);
    assert.ok(gone(Number(readFileSync(pidFile, "utf8"))));
  });

  it("aborting ends the run", async () => {
    const pidFile = join(ws, "a.pid");
    const ac = new AbortController();
    const done = run(c, `echo $$ > a.pid; exec sleep 300`, { shell: true, signal: ac.signal });
    while (!existsSync(pidFile) || !readFileSync(pidFile, "utf8").trim()) await new Promise((r) => setTimeout(r, 20));
    ac.abort();
    await assert.rejects(done, (e) => e.name === "AbortError");
    assert.ok(gone(Number(readFileSync(pidFile, "utf8"))));
  });

  it("disposal ends the run", async () => {
    // What `await using r = await c.spawn(...)` calls at the end of the
    // block (the syntax needs Node 24; the method works from 22).
    const r = await c.spawn(["/bin/sleep", "300"]);
    await r[Symbol.asyncDispose]();
    assert.ok(gone(r.pid));
  });

  it("the exit of the Node process ends its runs", () => {
    const script = `
      import { Cage, Policy } from "procage";
      const linux = ${MACOS} ? {} : { acceptSpawnSnapshot: true, relax: ["waive:trust-handoff"] };
      const c = new Cage(Policy.preset("agent_workspace", 3, { workspace: ${JSON.stringify(ws)} }), linux);
      const r = await c.spawn(["/bin/sleep", "300"]);
      console.log(r.pid);`;
    const pid = Number(execFileSync(process.execPath, ["--input-type=module", "-e", script], { cwd: fileURLToPath(new URL("..", import.meta.url)) }));
    assert.ok(gone(pid));
  });
});

describe("concurrency", () => {
  const ws = workspace();
  const c = cage(preset(ws));

  it("many runs at once, and the event loop stays free", async () => {
    const start = Date.now();
    let late = 0;
    const timer = setInterval(() => {
      const now = Date.now();
      late = Math.max(late, now - (timer.last ?? now));
      timer.last = now;
    }, 20);
    const done = await Promise.all(Array.from({ length: 6 }, (_, i) => run(c, `sleep 1; echo ${i}`, { shell: true })));
    clearInterval(timer);
    assert.deepEqual(done.map((d) => d.stdout), Array.from({ length: 6 }, (_, i) => `${i}\n`));
    assert.ok(Date.now() - start < 4000, "the runs ran at once");
    assert.ok(late < 500, `a 20 ms timer waited ${late} ms`);
  });
});

describe("records", () => {
  it("violations name what was denied", async () => {
    const ws = workspace();
    const outside = workspace();
    writeFileSync(join(outside, "f"), "x");
    const c = cage(withNode(preset(ws)), { violations: true });
    let done;
    if (MACOS) {
      done = await run(c, ["/bin/cat", join(outside, "f")], { cwd: ws });
      assert.ok(done.violations.some((v) => v.target === join(outside, "f")), JSON.stringify(done.violations));
    } else {
      // Linux reports refused system calls: leaving the run's session.
      done = await run(c, [process.execPath, "-e", "try { require('child_process').execFileSync('/usr/bin/setsid', ['true']) } catch {}"], { cwd: ws });
      assert.ok(done.violations.some((v) => v.operation === "setsid"), JSON.stringify(done.violations));
    }
    assert.ok(done.violations.every((v) => v.message));
  });

  it("the receipt parses", async () => {
    const done = await run(cage(preset(workspace())), ["/usr/bin/true"]);
    assert.equal(done.exitCode, 0);
    assert.ok(done.receipt.backend);
  });

  it("an undeclared grant is refused", async () => {
    const ws = workspace();
    await assert.rejects(cage(preset(ws)).spawn(["/usr/bin/true"], { grants: { nope: ws } }), GrantError);
  });
});

describe("loader", () => {
  it("loads the packaged addon whatever the environment says", () => {
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", `import("procage").then(() => console.log("ok"))`], {
      env: { ...process.env, NAPI_RS_NATIVE_LIBRARY_PATH: "/nonexistent/evil.node" },
      cwd: fileURLToPath(new URL("..", import.meta.url)),
    });
    assert.equal(String(out).trim(), "ok");
  });
});

describe("example", () => {
  it("the shell tool runs a command", () => {
    const ws = workspace();
    const example = fileURLToPath(new URL("../examples/shell-tool.js", import.meta.url));
    const out = execFileSync(process.execPath, [example, ws, "echo caged > note && cat note"], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
    });
    assert.match(String(out), /caged/);
  });
});
