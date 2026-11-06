#!/usr/bin/env node
// Refreshes the embedded trust anchors in src/trust/ from their publishers:
//
//   - the Sigstore trusted root: the trusted_root.json target of the Sigstore
//     TUF repository, fetched by a TUF client bootstrapped from the
//     repository's first root (scripts/sigstore-tuf-root.json) and walked
//     through every root rotation since, so the target is authenticated by
//     the TUF root of trust; the bytes are embedded as served;
//   - the AMD SEV-SNP certificate chains (ASK then ARK) for each supported
//     product line, from the AMD Key Distribution Service;
//   - the Intel SGX Root CA, from Intel's certificate service.
//
// Every certificate chain is parsed and checked before anything is written:
// the expected number of certificates, each one signed by the next, and the
// last one self-signed. Nothing is written unless every source fetched and
// checked, so the generated modules and SOURCE always agree.
//
// The AMD and Intel roots are self-signed, so nothing but the publisher's
// transport authenticates a fetch of them, and they are not expected to
// change for decades. The committed copies therefore act as pins: a fetched
// chain whose certificates differ from the committed ones is refused, with
// both fingerprints printed, unless --accept-root-change is given. The
// Sigstore root is authenticated by TUF and changes routinely, so it is
// always accepted.
//
// Tinfoil's signing key in src/trust/signing-keys.ts is maintained by
// hand, not fetched.
//
//   npm run sync:trust [-- --accept-root-change]
//
// Each module exports one string constant. src/trust/SOURCE records where
// each file came from, when, and the SHA-256 of the embedded bytes.
import { X509Certificate } from "@freedomofpress/sigstore-browser";
import { TUFClient } from "@freedomofpress/tuf-browser";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "src", "trust");
const acceptRootChange = process.argv.includes("--accept-root-change");

const SIGSTORE_TUF = "https://tuf-repo-cdn.sigstore.dev/";
const AMD_KDS = "https://kdsintf.amd.com/vcek/v1";
const INTEL_SGX_ROOT = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem";

/** The certificates of a PEM chain, parsed; the text must be nothing but certificate blocks. */
function parseChain(text, what) {
  const blocks = text.match(/-----BEGIN CERTIFICATE-----\n[\s\S]*?\n-----END CERTIFICATE-----\n/g) ?? [];
  if (blocks.join("") !== text) throw new Error(`${what}: not a PEM certificate chain`);
  return blocks.map((b) => X509Certificate.parse(b));
}

const fingerprint = (cert) => createHash("sha256").update(cert.root.toDER()).digest("hex");

/** The committed chain's certificates, or [] when the module does not exist yet; any other read failure propagates, so that it cannot bypass the pin. */
function committedChain(name) {
  let module;
  try {
    module = readFileSync(join(out, name), "utf8");
  } catch (err) {
    if (err?.code === "ENOENT") return [];
    throw err;
  }
  const text = JSON.parse(module.slice(module.indexOf("= ") + 2, module.lastIndexOf(";")));
  return parseChain(text, name);
}

async function fetchChain(name, url, expectedCount) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  // Publishers differ in line endings; the certificates are what matter.
  let text = (await res.text()).replace(/\r\n/g, "\n");
  if (!text.endsWith("\n")) text += "\n";
  const certs = parseChain(text, url);
  if (certs.length !== expectedCount) throw new Error(`${url}: expected ${expectedCount} certificates, got ${certs.length}`);
  for (let i = 0; i < certs.length; i++) {
    const issuer = certs[i + 1];
    if (!(await certs[i].verify(issuer))) throw new Error(`${url}: certificate ${i} is not signed by ${issuer ? "the next certificate" : "itself"}`);
  }
  const committed = committedChain(name);
  const changed = committed.length !== certs.length || certs.some((c, i) => fingerprint(c) !== fingerprint(committed[i]));
  if (changed && committed.length > 0 && !acceptRootChange) {
    throw new Error(
      `${url}: the fetched chain differs from the committed ${name}\n` +
        `  committed: ${committed.map(fingerprint).join(", ")}\n` +
        `  fetched:   ${certs.map(fingerprint).join(", ")}\n` +
        "  A trust anchor changing is unexpected; rerun with --accept-root-change only after confirming the new chain out of band.",
    );
  }
  return text;
}

async function fetchSigstoreRoot() {
  const bootstrap = readFileSync(join(here, "sigstore-tuf-root.json"), "utf8");
  const client = new TUFClient(SIGSTORE_TUF, bootstrap, "sync-trust", `${SIGSTORE_TUF}targets/`, { disableCache: true });
  await client.updateTUF();
  const target = new TextDecoder("utf-8", { fatal: true }).decode(await client.getTarget("trusted_root.json"));
  JSON.parse(target); // must be a single JSON document
  return target;
}

const files = [
  {
    name: "sigstore-trusted-root.ts",
    constant: "SIGSTORE_TRUSTED_ROOT_JSON",
    doc: "The Sigstore public-good trusted root all provenance bundles verify against.",
    source: `${SIGSTORE_TUF} target trusted_root.json (raw bytes)`,
    fetch: fetchSigstoreRoot,
  },
  {
    name: "amd-genoa-chain.ts",
    constant: "AMD_GENOA_CERT_CHAIN_PEM",
    doc: "AMD KDS certificate chain for Genoa: the ASK followed by the self-signed ARK.",
    source: `${AMD_KDS}/Genoa/cert_chain`,
    fetch: () => fetchChain("amd-genoa-chain.ts", `${AMD_KDS}/Genoa/cert_chain`, 2),
  },
  {
    name: "amd-turin-chain.ts",
    constant: "AMD_TURIN_CERT_CHAIN_PEM",
    doc: "AMD KDS certificate chain for Turin: the ASK followed by the self-signed ARK.",
    source: `${AMD_KDS}/Turin/cert_chain`,
    fetch: () => fetchChain("amd-turin-chain.ts", `${AMD_KDS}/Turin/cert_chain`, 2),
  },
  {
    name: "intel-sgx-root.ts",
    constant: "INTEL_SGX_ROOT_CA_PEM",
    doc: "The Intel SGX Root CA that anchors every TDX PCK certificate chain.",
    source: INTEL_SGX_ROOT,
    fetch: () => fetchChain("intel-sgx-root.ts", INTEL_SGX_ROOT, 1),
  },
];

// Fetch and check everything first; write nothing on failure.
const fetched = [];
for (const f of files) {
  const text = await f.fetch();
  fetched.push({ ...f, text, sha256: createHash("sha256").update(text).digest("hex") });
}

const record = [`fetched ${new Date().toISOString()} by scripts/sync-trust.mjs; sha256 is of the embedded bytes`, ""];
for (const f of fetched) {
  writeFileSync(
    join(out, f.name),
    `// Generated by scripts/sync-trust.mjs. Do not edit; run \`npm run sync:trust\`.\n\n/** ${f.doc} */\nexport const ${f.constant} = ${JSON.stringify(f.text)};\n`,
  );
  record.push(f.name, `  source: ${f.source}`, `  sha256: ${f.sha256}`);
  console.log(`${f.name}: ${f.sha256.slice(0, 16)}… from ${f.source}`);
}
writeFileSync(join(out, "SOURCE"), record.join("\n") + "\n");
