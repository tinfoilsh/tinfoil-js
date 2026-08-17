#!/usr/bin/env node
// tinfoil-js v3 conformance adapter (Go: cmd/tinfoil-conformance +
// verifier/conformance/conformance.go).
//
//   node cli.js <stage>        Input JSON on stdin -> Output JSON on stdout,
//                              exit code = verdict
//   node cli.js capabilities   self-description JSON on stdout, exit 0
//
// Exit codes are the cross-SDK adapter contract: the suite reads them to
// decide pass/skip and never depends on stdout for the verdict.
//
// Thin Node wrapper: stdin/stdout/exit only. The stage logic lives in run.ts
// (engine-neutral, shared with the browser conformance test).

import { capabilities } from "./capabilities.js";
import { ExitAccepted, ExitInternal, ExitMalformed, runStage, type Input } from "./run.js";

export {
  ExitAccepted,
  ExitInternal,
  ExitMalformed,
  ExitRejected,
  ExitUnsupported,
  type Input,
  type Output,
} from "./run.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString("utf-8");
}

function writeJSON(v: unknown): void {
  process.stdout.write(JSON.stringify(v, null, 2) + "\n");
}

async function main(): Promise<number> {
  const cmd = process.argv[2];
  if (cmd === undefined || cmd === "") {
    process.stderr.write("usage: tinfoil-conformance <stage>|capabilities\n");
    return ExitInternal;
  }

  if (cmd === "capabilities") {
    writeJSON(capabilities());
    return ExitAccepted;
  }

  let input: Input;
  try {
    input = JSON.parse(await readStdin()) as Input;
  } catch {
    writeJSON({ stage: cmd, accepted: false, rejection: { code: "MALFORMED_INPUT" } });
    return ExitMalformed;
  }

  const { output, exitCode } = await runStage(cmd, input);
  writeJSON(output);
  return exitCode;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`internal error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
    process.exitCode = ExitInternal;
  },
);
