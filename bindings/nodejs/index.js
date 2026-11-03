// procage: run commands caged by the operating system's sandbox.
//
// macOS uses Seatbelt; Linux uses Landlock, seccomp and, where the host
// allows, user namespaces. A policy comes from a preset or from procage's
// versioned JSON format; JavaScript never writes sandbox rules itself.
//
//   import { Policy, run } from "procage";
//   const policy = Policy.preset("agent_workspace", 3, { workspace: "/abs/project" });
//   const done = await run(policy, "npm test", { shell: true, timeout: 600_000 });
//
// See https://hupe1980.github.io/procage/docs/nodejs/.

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** A path from a string or a `file:` URL, without a trailing slash. */
const pathOf = (p) => {
  const path = p instanceof URL ? fileURLToPath(p) : String(p);
  return path.length > 1 ? path.replace(/\/+$/, "") : path;
};

// ---- Errors ----

/** Every procage error. */
export class ProcageError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}
/** An invalid policy document, preset or relaxation. */
export class PolicyError extends ProcageError {}
/** The host cannot enforce the policy; `gaps` lists what and how to accept it. */
export class CapabilityGapError extends ProcageError {
  constructor(message, gaps) {
    super(message);
    this.gaps = gaps;
  }
}
/** The host lacks something procage needs, or a setting cannot apply. */
export class UnsupportedError extends ProcageError {}
/** The calling process is itself sandboxed (macOS). */
export class AlreadySandboxedError extends ProcageError {}
/** A grant binding is undeclared, reserved or missing. */
export class GrantError extends ProcageError {}
/** The spawn failed (a path, a descriptor, the child sequence, I/O). */
export class SpawnError extends ProcageError {}
/** The run did not end within `timeout`; it was ended. */
export class TimeoutError extends ProcageError {
  constructor(message, result) {
    super(message);
    this.result = result;
  }
}
/** `check: true` and the command exited non-zero; `result` is what it did. */
export class ExitError extends ProcageError {
  constructor(message, result) {
    super(message);
    this.result = result;
  }
}

const KINDS = {
  PolicyError,
  CapabilityGapError,
  UnsupportedError,
  AlreadySandboxedError,
  GrantError,
  SpawnError,
};

/** The addon's errors carry `procage:{json}`; anything else passes through. */
function typed(error) {
  const text = error?.message ?? "";
  if (!text.startsWith("procage:")) return error;
  const { kind, message, gaps } = JSON.parse(text.slice("procage:".length));
  if (kind === "CapabilityGapError") {
    const hints = [];
    const seen = new Set();
    for (const g of gaps) {
      if (g.accept.length && !seen.has(g.construct)) {
        seen.add(g.construct);
        hints.push(`\n  ${g.construct}: new Cage(policy, { ${g.accept.join(" } or { ")} }) accepts it`);
      }
    }
    return new CapabilityGapError(message + hints.join(""), gaps);
  }
  return new (KINDS[kind] ?? ProcageError)(message);
}

function call(fn) {
  try {
    return fn();
  } catch (e) {
    throw typed(e);
  }
}

async function wait(promise) {
  try {
    return await promise;
  } catch (e) {
    throw typed(e);
  }
}

// ---- The addon: only this package's file for this platform ----

function platformTag() {
  const { platform, arch } = process;
  if (platform === "darwin" && arch === "arm64") return "darwin-arm64";
  if (platform === "linux" && (arch === "x64" || arch === "arm64")) {
    const glibc = process.report?.getReport?.().header?.glibcVersionRuntime;
    if (glibc) return `linux-${arch}-gnu`;
  }
  return null;
}

const tag = platformTag();
const file = tag && new URL(`./procage.${tag}.node`, import.meta.url);
if (!file || !existsSync(file)) {
  throw new UnsupportedError(
    `procage has no binary for ${process.platform}-${process.arch}` +
      " (supported: macOS arm64, Linux x64 and arm64 with glibc)",
  );
}
const native = createRequire(import.meta.url)(file.pathname);

// ---- Policies and cages ----

/** A policy: a preset or a document in the versioned JSON format. */
export class Policy {
  #native;
  constructor(handle) {
    this.#native = handle;
  }
  /**
   * A preset by name and version; every preset but `minimal` needs an
   * absolute `workspace`, which becomes its runs' working directory.
   */
  static preset(name, version, { workspace } = {}) {
    return new Policy(call(() => native.Policy.preset(name, version, workspace == null ? undefined : pathOf(workspace))));
  }
  /** A policy from the versioned JSON format (a string or an object). */
  static fromJSON(doc) {
    const text = typeof doc === "string" ? doc : JSON.stringify(doc);
    return new Policy(call(() => native.Policy.fromJson(text)));
  }
  /** The versioned JSON document (also used by `JSON.stringify`). */
  toJSON() {
    return JSON.parse(call(() => this.#native.toJson()));
  }
  /** The preset's workspace, else `null`. */
  get workspace() {
    return this.#native.workspace ?? null;
  }
  /** @internal */
  get handle() {
    return this.#native;
  }
}

/** A prepared policy; spawn any number of runs from it. */
export class Cage {
  #native;
  /**
   * `violations` records what the sandbox denied. `relax` names
   * relaxations to fit a host that cannot enforce everything;
   * `acceptSpawnSnapshot` accepts the Linux approximations taken at spawn.
   * A gap throws `CapabilityGapError`, naming the option that would accept
   * it; nothing is accepted unless passed.
   */
  constructor(policy, { violations = false, relax = [], acceptSpawnSnapshot = false } = {}) {
    this.#native = call(() => new native.Cage(policy.handle, { violations, relax, acceptSpawnSnapshot }));
  }
  /** The relaxations applied, as sentences. */
  get relaxed() {
    return this.#native.relaxed;
  }
  /**
   * Starts `command` caged: an array of arguments, or with `shell: true` one
   * command line for `/bin/sh -c`. Only `env` is set explicitly; the policy
   * decides which of this process's variables reach the child.
   */
  async spawn(command, { shell = false, cwd, env, grants, stdin = false } = {}) {
    const handle = await wait(
      this.#native.spawn(argv(command, shell), {
        cwd: cwd == null ? undefined : pathOf(cwd),
        env: env && Object.fromEntries(Object.entries(env).map(([k, v]) => [k, String(v)])),
        grants: grants && Object.fromEntries(Object.entries(grants).map(([k, v]) => [k, pathOf(v)])),
        stdin,
      }),
    );
    return new Run(handle);
  }
}

function argv(command, shell) {
  if (shell) {
    if (typeof command !== "string") throw new TypeError("with shell: true, the command is one string");
    return ["/bin/sh", "-c", command];
  }
  if (typeof command === "string") throw new TypeError("the command is an array; pass shell: true to run a command line");
  return command.map(String);
}

// ---- Runs ----

const live = new Set();
process.on("exit", () => {
  for (const r of live) r.close();
});

/** A caged command. Kill, close, dispose or collect it to end the run. */
export class Run {
  #native;
  constructor(handle) {
    this.#native = handle;
    live.add(this);
  }
  /** The child's process id. */
  get pid() {
    return this.#native.pid;
  }
  /** Resolves when the child exits: `{ exitCode, signal }`. */
  wait() {
    return wait(this.#native.wait());
  }
  /**
   * Writes `input`, reads standard output and error to the end and waits:
   * `{ exitCode, signal, stdout, stderr, timedOut }` with Buffers.
   */
  output({ input, timeout } = {}) {
    const data = input == null ? undefined : Buffer.from(input);
    return wait(this.#native.output(data, timeout));
  }
  /** Ends the run now: the child and every process it started. */
  kill() {
    call(() => this.#native.kill());
  }
  /** What the sandbox denied (when the cage records violations). */
  violations() {
    return wait(this.#native.violations());
  }
  /** How the run was caged, once the child has exited (this ends it). */
  receipt() {
    const text = call(() => this.#native.receiptJson());
    return text == null ? null : JSON.parse(text);
  }
  /** Ends the run and releases the handle. */
  close() {
    live.delete(this);
    this.#native.close();
  }
  [Symbol.dispose]() {
    this.close();
  }
  async [Symbol.asyncDispose]() {
    this.close();
  }
}

/**
 * Runs `command` caged to the end. `shell: true` runs one command line;
 * `encoding: "buffer"` keeps the output as Buffers; `input` is written to
 * standard input; `timeout` (milliseconds) ends the run and rejects with
 * `TimeoutError`; an aborted `signal` ends it and rejects with the
 * signal's reason; `check: true` rejects with `ExitError` on a non-zero
 * exit. Resolves to `{ command, exitCode, signal, stdout, stderr,
 * violations, receipt }`.
 */
export async function run(policyOrCage, command, options = {}) {
  const { input, timeout, signal, encoding = "utf8", check = false, ...spawn } = options;
  signal?.throwIfAborted();
  const cage = policyOrCage instanceof Cage ? policyOrCage : new Cage(policyOrCage);
  const r = await cage.spawn(command, { ...spawn, stdin: input != null });
  const onAbort = () => r.kill();
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const out = await r.output({ input, timeout });
    signal?.throwIfAborted();
    const decode = (b) => (encoding === "buffer" ? b : b.toString(encoding));
    const result = {
      command: argv(command, spawn.shell ?? false),
      exitCode: out.exitCode,
      signal: out.signal,
      stdout: decode(out.stdout),
      stderr: decode(out.stderr),
      violations: await r.violations(),
      receipt: out.timedOut ? null : r.receipt(),
    };
    if (out.timedOut) throw new TimeoutError(`the run did not end within ${timeout} ms`, result);
    if (check && result.exitCode !== 0) {
      throw new ExitError(
        `the command exited with ${result.exitCode ?? result.signal}`,
        result,
      );
    }
    return result;
  } finally {
    signal?.removeEventListener("abort", onAbort);
    r.close();
  }
}
