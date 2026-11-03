// A shell tool for an agent (or an MCP server), caged by procage.
//
// Register `shell` as a tool: it runs one command line in the workspace and
// returns what the model needs to read, including what the sandbox refused.
// The model's commands can read and write the workspace, run the system's
// programs and nothing else: no network, no secrets, no writes outside it.
//
//   node shell-tool.js /abs/workspace "ls -la"

import { Cage, Policy, TimeoutError, run } from "procage";

const cages = new Map();

/** One cage per workspace, reused by every call. */
function cageFor(workspace) {
  if (!cages.has(workspace)) {
    const policy = Policy.preset("agent_workspace", 3, { workspace });
    const linux = process.platform === "linux"
      // Linux: accept the masks taken at spawn, and waive trust-handoff
      // where the tier cannot keep it beside a write rule.
      ? { acceptSpawnSnapshot: true, relax: ["waive:trust-handoff"] }
      : {};
    cages.set(workspace, new Cage(policy, { violations: true, ...linux }));
  }
  return cages.get(workspace);
}

/** Runs `command` with /bin/sh in `workspace`, caged, and reports it. */
export async function shell(command, workspace, { timeout = 60_000, signal } = {}) {
  try {
    const done = await run(cageFor(workspace), command, { shell: true, timeout, signal });
    return [
      `exit code: ${done.exitCode ?? done.signal}`,
      done.stdout,
      done.stderr && `stderr:\n${done.stderr}`,
      ...done.violations.map((v) => `refused: ${v.message}`),
    ].filter(Boolean).join("\n");
  } catch (e) {
    if (e instanceof TimeoutError) return `timed out after ${timeout} ms`;
    throw e;
  }
}

if (import.meta.main ?? process.argv[1] === new URL(import.meta.url).pathname) {
  console.log(await shell(process.argv[3], process.argv[2]));
}
