#!/usr/bin/env node
// Standalone wire-protocol adapter for the v3-authenticate-quote stage,
// SEV-SNP slice only (Go: verifier/conformance StageAuthenticateQuote).
//
//   node quote-sev-stage.mjs v3-authenticate-quote
//     Input JSON on stdin -> Output JSON on stdout,
//     exit 0 accepted / 10 rejected / 20 unsupported / 30 malformed.
//
// TDX documents and other stages exit 20 so the suite skips them.

import { readFileSync } from "node:fs";
import {
  parseDocument,
  SEVSNPReportV1Format,
  VerificationError,
} from "../../verifier/dist/v3/index.js";
import { sevAuthenticate } from "../../verifier/dist/v3/sev/index.js";

const ExitAccepted = 0;
const ExitInternal = 1;
const ExitRejected = 10;
const ExitUnsupported = 20;
const ExitMalformed = 30;

const StageAuthenticateQuote = "v3-authenticate-quote";

function emit(output, code) {
  process.stdout.write(JSON.stringify(output) + "\n");
  process.exit(code);
}

function malformed(stage) {
  emit({ stage, accepted: false, rejection: { code: "MALFORMED_INPUT" } }, ExitMalformed);
}

const stage = process.argv[2] ?? "";
if (stage !== StageAuthenticateQuote) {
  emit({ stage, accepted: false }, ExitUnsupported);
}

let input;
try {
  input = JSON.parse(readFileSync(0, "utf8"));
} catch {
  malformed(stage);
}

let docBytes;
try {
  docBytes = new Uint8Array(Buffer.from(input.document_b64 ?? "", "base64"));
} catch {
  malformed(stage);
}

// AMD anchor: ARK plus its ASK, both or neither (Go Input.roots). The KDS
// cert_chain order is ASK then ARK.
const arkPEM = input.amd_root_ca_pem ?? "";
const askPEM = input.ask_pem ?? "";
let rootPEM;
if (arkPEM !== "" && askPEM !== "") {
  rootPEM = askPEM.trim() + "\n" + arkPEM.trim() + "\n";
} else if (arkPEM !== "" || askPEM !== "") {
  malformed(stage); // amd_root_ca_pem and ask_pem must be supplied together
}

// verification_time_unix pins the quote-layer clock; 0/absent uses now.
let now;
if (input.verification_time_unix) {
  now = new Date(input.verification_time_unix * 1000);
}

let doc;
try {
  doc = parseDocument(docBytes);
} catch {
  malformed(stage);
}

if (doc.cpuEvidence.format !== SEVSNPReportV1Format) {
  emit({ stage, accepted: false }, ExitUnsupported);
}

try {
  const quote = await sevAuthenticate(doc, { rootPEM, now });
  emit(
    {
      stage,
      accepted: true,
      outputs: {
        enclave_measurement: { type: quote.measurement.type, registers: quote.measurement.registers },
      },
    },
    ExitAccepted,
  );
} catch (err) {
  if (err instanceof VerificationError) {
    emit({ stage, accepted: false, rejection: { code: "QUOTE_REJECTED" } }, ExitRejected);
  }
  process.stderr.write(String(err && err.stack ? err.stack : err) + "\n");
  process.exit(ExitInternal);
}
