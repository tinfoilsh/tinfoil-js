#!/usr/bin/env node
/**
 * tinfoil-conformance CLI for tinfoil-js. Test tooling, not published: build
 * with `npm run build:conformance -w @tinfoilsh/verifier`, then point the
 * suite at `node packages/verifier/dist-conformance/conformance/cli.js`.
 *
 *   tinfoil-conformance <stage>        Input JSON on stdin → Output JSON on stdout
 *   tinfoil-conformance capabilities   capabilities JSON on stdout
 *   tinfoil-conformance live-verify    {"host","repo"[,"project"]} on stdin → Output JSON on stdout
 *   tinfoil-conformance capture        (not yet supported)
 *
 * The exit code is the verdict (see ExitCode in adapter.ts).
 */
import { capabilities, ExitCode, run, type Output } from "./adapter.js";
import { decodeLiveRequest, liveVerify, STAGE_LIVE } from "./live.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function writeJSON(v: unknown): void {
  process.stdout.write(JSON.stringify(v, null, 2) + "\n");
}

async function main(argv: string[]): Promise<number> {
  const cmd = argv[0];
  if (cmd === undefined) {
    process.stderr.write("usage: tinfoil-conformance <stage>|capabilities|capture|live-verify\n");
    return ExitCode.Malformed;
  }

  if (cmd === "capabilities") {
    writeJSON(capabilities());
    return ExitCode.Accepted;
  }

  // TODO(v3): fixture capture.
  if (cmd === "capture") {
    writeJSON({ stage: cmd, accepted: false } satisfies Output);
    return ExitCode.Unsupported;
  }

  // Exactly one JSON value; JSON.parse rejects trailing data.
  let raw: unknown;
  try {
    raw = JSON.parse(await readStdin());
  } catch {
    writeJSON({ stage: cmd, accepted: false, rejection: { code: "MALFORMED_INPUT" } } satisfies Output);
    return ExitCode.Malformed;
  }

  if (cmd === STAGE_LIVE) {
    const req = decodeLiveRequest(raw);
    if (req === undefined) {
      writeJSON({ stage: cmd, accepted: false, rejection: { code: "MALFORMED_INPUT" } } satisfies Output);
      return ExitCode.Malformed;
    }
    const { output, exitCode } = await liveVerify(req, (line) => process.stderr.write(line + "\n"));
    writeJSON(output);
    return exitCode;
  }

  const { output, exitCode } = await run(cmd, raw);
  writeJSON(output);
  return exitCode;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`internal error: ${String(err)}\n`);
    process.exitCode = ExitCode.Internal;
  },
);
