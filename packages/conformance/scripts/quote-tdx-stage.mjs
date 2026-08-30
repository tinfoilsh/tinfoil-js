#!/usr/bin/env node
// Standalone v3-authenticate-quote adapter, TDX only: reads the wire Input
// on stdin, runs tdxAuthenticate against the fixture's pinned Intel root and
// verification time, and emits the wire Output. Exit codes: 0 accepted,
// 10 rejected, 20 unsupported (stage or non-TDX cpu_evidence), 30 malformed.

import { parseDocument, TDXQuoteV1Format, VerificationError } from "../../verifier/dist/v3/index.js";
import { tdxAuthenticate } from "../../verifier/dist/v3/tdx/authenticate.js";

const STAGE = "v3-authenticate-quote";

function emit(obj, code) {
  process.stdout.write(JSON.stringify(obj) + "\n");
  process.exit(code);
}

function malformed(stage) {
  emit({ stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, 30);
}

async function main() {
  const stage = process.argv[2] ?? "";
  if (stage !== STAGE) {
    emit({ stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, 20);
  }

  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    malformed(stage);
  }
  if (typeof input !== "object" || input === null || typeof input.document_b64 !== "string") {
    malformed(stage);
  }

  let docBytes;
  try {
    docBytes = new Uint8Array(Buffer.from(input.document_b64, "base64"));
  } catch {
    malformed(stage);
  }

  const opts = {};
  if (typeof input.intel_sgx_root_pem === "string" && input.intel_sgx_root_pem !== "") {
    opts.rootPEM = input.intel_sgx_root_pem;
  }
  if (typeof input.verification_time_unix === "number" && input.verification_time_unix > 0) {
    opts.now = new Date(input.verification_time_unix * 1000);
  }

  try {
    const doc = parseDocument(docBytes);
    if (doc.cpuEvidence.format !== TDXQuoteV1Format) {
      // Non-TDX evidence is another adapter's job.
      emit({ stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, 20);
    }
    const quote = await tdxAuthenticate(doc, opts);
    emit(
      {
        stage,
        accepted: true,
        outputs: {
          enclave_measurement: {
            type: quote.measurement.type,
            registers: quote.measurement.registers,
          },
        },
      },
      0,
    );
  } catch (err) {
    if (err instanceof VerificationError) {
      emit({ stage, accepted: false, rejection: { code: err.layer } }, 10);
    }
    process.stderr.write(String(err && err.stack ? err.stack : err) + "\n");
    malformed(stage);
  }
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err) + "\n");
  process.exit(30);
});
