#!/usr/bin/env node
/**
 * Tinfoil-flavored conformance binary for tinfoil-js.
 *
 * CLI contract: tinfoil-conformance/schemas/.
 *
 * Subcommands:
 *   tinfoil-conformance capabilities                # stdin: none, stdout: JSON
 *   tinfoil-conformance verify-sigstore             # stdin: JSON, stdout: JSON
 *
 * Exit codes:
 *   0  accepted
 *   10 rejected (rejection.code populated)
 *   20 stage/capability not supported
 *   30 malformed input
 *   1  internal error
 */

import { capabilities } from './capabilities.js';
import { verifyAttestationSev } from './verify-attestation-sev.js';
import { verifyFull } from './verify-full.js';
import { verifyHardwareMeasurements } from './verify-hardware-measurements.js';
import { verifyMeasurement } from './verify-measurement.js';
import { verifySigstore } from './verify-sigstore.js';

const EXIT = {
  accept: 0,
  reject: 10,
  unsupported: 20,
  badInput: 30,
  internal: 1,
} as const;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

function printHelp(): void {
  process.stderr.write(
    `tinfoil-conformance: Tinfoil cross-SDK conformance binary (tinfoil-js)\n\n` +
      `Subcommands:\n` +
      `  capabilities      Print SDK capabilities JSON\n` +
      `  verify-sigstore   Verify a Sigstore bundle (SPEC §5)\n\n` +
      `I/O contract: stdin JSON, stdout JSON. See tinfoil-conformance/schemas/.\n`,
  );
}

async function main(): Promise<number> {
  const sub = process.argv[2] ?? '';
  switch (sub) {
    case 'capabilities': {
      const caps = capabilities();
      process.stdout.write(JSON.stringify(caps, null, 2) + '\n');
      return EXIT.accept;
    }
    case 'verify-sigstore': {
      const raw = await readStdin();
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        process.stdout.write(
          JSON.stringify(
            {
              stage: 'verify-sigstore',
              accepted: false,
              rejection: {
                code: 'BUNDLE_MALFORMED',
                spec_ref: '5.2',
                message: `input is not valid JSON: ${(e as Error).message}`,
              },
            },
            null,
            2,
          ) + '\n',
        );
        return EXIT.badInput;
      }
      const { exitCode, body } = await verifySigstore(parsed);
      process.stdout.write(JSON.stringify(body, null, 2) + '\n');
      return exitCode;
    }
    case 'verify-measurement': {
      const raw = await readStdin();
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        process.stderr.write(`input is not valid JSON: ${(e as Error).message}\n`);
        return EXIT.badInput;
      }
      const { exitCode, body } = await verifyMeasurement(parsed);
      process.stdout.write(JSON.stringify(body, null, 2) + '\n');
      return exitCode;
    }
    case 'verify-hardware-measurements': {
      const raw = await readStdin();
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        process.stderr.write(`input is not valid JSON: ${(e as Error).message}\n`);
        return EXIT.badInput;
      }
      const { exitCode, body } = await verifyHardwareMeasurements(parsed);
      process.stdout.write(JSON.stringify(body, null, 2) + '\n');
      return exitCode;
    }
    case 'verify-attestation-sev': {
      const raw = await readStdin();
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        process.stderr.write(`input is not valid JSON: ${(e as Error).message}\n`);
        return EXIT.badInput;
      }
      const { exitCode, body } = await verifyAttestationSev(parsed);
      process.stdout.write(JSON.stringify(body, null, 2) + '\n');
      return exitCode;
    }
    case 'verify-full': {
      const raw = await readStdin();
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        process.stderr.write(`input is not valid JSON: ${(e as Error).message}\n`);
        return EXIT.badInput;
      }
      const { exitCode, body } = await verifyFull(parsed);
      process.stdout.write(JSON.stringify(body, null, 2) + '\n');
      return exitCode;
    }
    case 'help':
    case '--help':
    case '-h':
    case '':
      printHelp();
      return EXIT.accept;
    default:
      process.stderr.write(`tinfoil-conformance: unknown subcommand '${sub}'\n`);
      printHelp();
      return EXIT.badInput;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`internal error: ${(err as Error).stack ?? err}\n`);
    process.exit(EXIT.internal);
  },
);
