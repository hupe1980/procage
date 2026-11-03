/** Every procage error. */
export class ProcageError extends Error {}
/** An invalid policy document, preset or relaxation. */
export class PolicyError extends ProcageError {}
/** One construct the host cannot enforce, and the options that would accept it. */
export interface Gap {
  construct: string;
  target: string;
  kind: string;
  subject: string | null;
  /** E.g. `acceptSpawnSnapshot: true` or `relax: ["waive:trust-handoff"]`; empty when none does. */
  accept: string[];
}
/** The host cannot enforce the policy. */
export class CapabilityGapError extends ProcageError {
  readonly gaps: Gap[];
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
  readonly result: Result<string | Buffer>;
}
/** `check: true` and the command exited non-zero. */
export class ExitError extends ProcageError {
  readonly result: Result<string | Buffer>;
}

export type PresetName = "minimal" | "agent_readonly" | "agent_workspace" | "build";

/** A policy: a preset or a document in the versioned JSON format. */
export class Policy {
  private constructor();
  /** Every preset but `minimal` needs an absolute workspace, its runs' working directory. */
  static preset(name: PresetName, version: 1 | 2 | 3, options?: { workspace?: string | URL }): Policy;
  /** A policy from the versioned JSON format; unknown fields throw `PolicyError`. */
  static fromJSON(doc: string | object): Policy;
  toJSON(): object;
  /** The preset's workspace, else `null`. */
  readonly workspace: string | null;
}

/** `leave-out-protect`, `leave-out-hide`, `no-unix-sockets`, `signals-same-user`, `no-loopback` or `waive:<class>`. */
export type Relaxation =
  | "leave-out-protect"
  | "leave-out-hide"
  | "no-unix-sockets"
  | "signals-same-user"
  | "no-loopback"
  | `waive:${string}`;

export interface CageOptions {
  /** Record what the sandbox denied. */
  violations?: boolean;
  /** Relaxations applied only where the host needs them. */
  relax?: Relaxation[];
  /** Accept the Linux approximations taken from the file system at spawn. */
  acceptSpawnSnapshot?: boolean;
}

export interface SpawnOptions {
  /** Run one command line with `/bin/sh -c`. */
  shell?: boolean;
  /** The working directory; the preset's workspace by default. */
  cwd?: string | URL;
  /** The only variables set explicitly (`process.env` is never copied). */
  env?: Record<string, string | number>;
  /** Paths bound to the policy's declared grants. */
  grants?: Record<string, string | URL>;
}

/** A prepared policy; spawn any number of runs from it. */
export class Cage {
  constructor(policy: Policy, options?: CageOptions);
  /** The relaxations applied, as sentences. */
  readonly relaxed: string[];
  spawn(command: string[], options?: SpawnOptions & { shell?: false; stdin?: boolean }): Promise<Run>;
  spawn(command: string, options: SpawnOptions & { shell: true; stdin?: boolean }): Promise<Run>;
}

export interface Exit {
  exitCode: number | null;
  signal: string | null;
}

/** One denial the sandbox reported. */
export interface Violation {
  pid: number;
  process: string;
  operation: string;
  target: string | null;
  deniedBy: string;
  repeats: number;
  /** The whole report as a sentence. */
  message: string;
}

/** A caged command. Kill, close, dispose (`using`) or collect it to end the run. */
export class Run implements Disposable, AsyncDisposable {
  private constructor();
  readonly pid: number;
  wait(): Promise<Exit>;
  output(options?: { input?: string | Uint8Array; timeout?: number }): Promise<
    Exit & { stdout: Buffer; stderr: Buffer; timedOut: boolean }
  >;
  kill(): void;
  violations(): Promise<Violation[]>;
  /** How the run was caged, once the child has exited (this ends it). */
  receipt(): Record<string, unknown> | null;
  close(): void;
  [Symbol.dispose](): void;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface Result<Out> extends Exit {
  command: string[];
  stdout: Out;
  stderr: Out;
  violations: Violation[];
  receipt: Record<string, unknown> | null;
}

export interface RunOptions extends SpawnOptions {
  /** Written to standard input. */
  input?: string | Uint8Array;
  /** Milliseconds; then the run is ended and `TimeoutError` thrown. */
  timeout?: number;
  /** Aborting ends the run and rejects with the signal's reason. */
  signal?: AbortSignal;
  /** Reject with `ExitError` on a non-zero exit. */
  check?: boolean;
}

/** Runs `command` caged to the end. */
export function run(
  policy: Policy | Cage,
  command: string[] | string,
  options?: RunOptions & { encoding?: BufferEncoding },
): Promise<Result<string>>;
export function run(
  policy: Policy | Cage,
  command: string[] | string,
  options: RunOptions & { encoding: "buffer" },
): Promise<Result<Buffer>>;
