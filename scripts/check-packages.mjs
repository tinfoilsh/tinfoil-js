import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { build } from "esbuild";

const root = fileURLToPath(new URL("../", import.meta.url));
const directory = await mkdtemp(join(tmpdir(), "tinfoil-packed-"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
function run(command, args, cwd = root, capture = false) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
    env: { ...process.env, NODE_PATH: "" },
  });
  if (result.status !== 0)
    throw new Error(
      `${command} ${args.join(" ")} failed\n${result.stdout ?? ""}${result.stderr ?? ""}`,
    );
  return result.stdout;
}
async function files(directory) {
  const result = [];
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, item.name);
    result.push(...(item.isDirectory() ? await files(path) : [path]));
  }
  return result;
}
try {
  run(npm, ["run", "build"]);
  const archives = [];
  for (const name of ["verifier", "tinfoil"]) {
    // Build above is explicit. Packing cannot mutate the source tree through
    // lifecycle hooks.
    const [packed] = JSON.parse(
      run(
        npm,
        [
          "pack",
          `./packages/${name}`,
          "--ignore-scripts",
          "--json",
          "--pack-destination",
          directory,
        ],
        root,
        true,
      ),
    );
    for (const file of packed.files) {
      assert(
        !/(?:^|\/)(?:src|test|tests|fixtures|conformance)(?:\/|$)|\.map$/.test(
          file.path,
        ),
        `Unexpected packed file: ${file.path}`,
      );
    }
    archives.push(join(directory, packed.filename));
  }
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  // This is an isolated consumer install, never a workspace dependency link.
  run(
    npm,
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      ...archives,
    ],
    directory,
  );
  for (const name of ["@tinfoilsh/verifier", "tinfoil"]) {
    const location = join(directory, "node_modules", name);
    assert(
      (await realpath(location)).startsWith(directory),
      `Workspace link substituted for packed ${name}`,
    );
    for (const file of await files(location)) {
      assert(!file.endsWith(".map"), `Source map shipped: ${file}`);
      if (/\.(?:js|ts)$/.test(file)) {
        const source = await readFile(file, "utf8");
        assert(
          !/createVerifierForConformance|provenanceOptionsForConformance|decodeDocumentForConformance|DangerousTestOnly|sourceMappingURL=/.test(
            source,
          ),
          `Private hook or source map shipped: ${file}`,
        );
      }
    }
  }
  const capture = JSON.parse(
    await readFile(
      join(root, "packages/verifier/test/fixtures/production-v3.json"),
      "utf8",
    ),
  );
  const smoke = `
import * as verifier from '@tinfoilsh/verifier';
import * as sdk from 'tinfoil';
import * as unsafe from 'tinfoil/unsafe';
const capture = ${JSON.stringify(capture)};
const check = (condition, message) => { if (!condition) throw new Error(message); };
const throws = (operation, type) => { let error; try { operation(); } catch (e) { error = e; } check(error instanceof type, 'Expected ' + type.name); };
export async function run() {
  check(verifier.randomNonce().length === 32, 'Nonce export');
  for (const name of ['createVerifierForConformance', 'provenanceOptionsForConformance', 'parseDocument', 'decodeDocumentForConformance']) check(!(name in verifier), 'Private export ' + name);
  for (const options of [{ sigstoreRoot: {} }, { amdRootPem: '' }, { intelRootPem: '' }, { verificationTime: new Date() }]) throws(() => new verifier.Verifier(options), verifier.UsageError);
  throws(() => Reflect.construct(verifier.Verification, []), verifier.UsageError);
  const bytes = Uint8Array.from(atob(capture.documentBase64), c => c.charCodeAt(0));
  const nonce = Uint8Array.from(capture.nonceHex.match(/../g), h => Number.parseInt(h, 16));
  const result = await new verifier.Verifier().verifyDocumentV3At(bytes, nonce, capture.identity, new Date(capture.capturedAt));
  check(Object.isFrozen(result), 'Immutable result');
  check(result.configRepo === capture.identity && !!result.tlsPublicKeyFingerprint() && !!result.hpkePublicKey(), 'Authenticated public facts');
  check(result.cryptoMaterialData('tls', verifier.KEY_TLS) === result.tlsPublicKeyFingerprint(), 'Generic key lookup');
  const deadline = result.freshnessExpiresAt.getTime(); result.freshnessExpiresAt.setTime(0);
  check(result.freshnessExpiresAt.getTime() === deadline, 'Detached deadline');
  check(JSON.stringify(result) === '{}', 'Result authority serialized');
  throws(() => Object.assign(Object.create(verifier.Verification.prototype), JSON.parse(JSON.stringify(result))).hpkePublicKey(), verifier.UsageError);
  throws(() => new sdk.SecureClient({ enclaveURL: 'https://example.test', configRepo: 'invalid' }), sdk.ConfigurationError);
  const direct = new sdk.SecureClient({ enclaveURL: 'https://example.test', configRepo: 'tinfoilsh/example' });
  check(direct.inspect() === undefined, 'Passive secure-client construction');
  const client = new sdk.TinfoilAI({ apiKey: 'package-test', dangerouslyAllowBrowser: true, maxRetries: 0 });
  check(client.chat.completions && client.responses && client.decisions && client.batches && client.uploads && client.vectorStores, 'Native provider resources');
  check(client.inspect() === undefined, 'Passive provider inspection');
  const provider = await sdk.createTinfoilAI('package-test', { gateway: { url: 'https://gateway.test', catalog: () => ({}) } });
  check(typeof provider('model').doGenerate === 'function', 'AI SDK provider export');
  const token = { exportedSecret: new Uint8Array([1, 2, 3]), requestEnc: new Uint8Array([4, 5, 6]) };
  const recovered = sdk.deserializeSessionRecoveryToken(sdk.serializeSessionRecoveryToken(token));
  check(String(recovered.exportedSecret) === '1,2,3' && String(recovered.requestEnc) === '4,5,6', 'Recovery-token serialization');
  check(typeof unsafe.UnverifiedClient === 'function' && !('UnverifiedClient' in sdk), 'Unsafe subpath isolation');
  return { identity: result.configRepo, tag: result.codeTag, expiry: result.freshnessExpiresAt.toISOString() };
}
`;
  await writeFile(join(directory, "smoke.mjs"), smoke);
  await writeFile(
    join(directory, "node.mjs"),
    `import assert from 'node:assert/strict';\nimport { run } from './smoke.mjs';\nglobalThis.fetch = () => { throw new Error('Packed smoke attempted network access'); };\nfor (const name of ['@tinfoilsh/verifier/dist/index.js', '@tinfoilsh/verifier/client', 'tinfoil/dist/client.js']) await assert.rejects(import(name), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });\nconsole.log('Packed Node entry:', await run());\n`,
  );
  run(process.execPath, ["node.mjs"], directory);

  const browser = await build({
    absWorkingDir: directory,
    entryPoints: ["smoke.mjs"],
    bundle: true,
    platform: "browser",
    format: "iife",
    globalName: "PackedSmoke",
    target: "es2020",
    write: false,
    metafile: true,
  });
  for (const input of Object.keys(browser.metafile.inputs))
    assert(
      resolve(directory, input).startsWith(directory),
      `Browser import escaped isolated install: ${input}`,
    );
  for (const output of Object.values(browser.metafile.outputs))
    assert(
      output.imports.every((item) => !item.external),
      "Browser bundle contains external imports",
    );
  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    URL,
    URLSearchParams,
    Headers,
    Request,
    Response,
    AbortController,
    AbortSignal,
    DOMException,
    ReadableStream,
    TransformStream,
    atob,
    btoa,
    structuredClone,
    setTimeout,
    clearTimeout,
    console,
    fetch: () => {
      throw new Error("Browser smoke attempted network access");
    },
    navigator: { userAgent: "package-test-browser" },
    document: {},
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(browser.outputFiles[0].text, sandbox, { timeout: 10000 });
  console.log(
    "Packed browser entry without Node globals:",
    await sandbox.PackedSmoke.run(),
  );

  await writeFile(
    join(directory, "public.ts"),
    `
import TinfoilAI, { SecureClient, Client, Gateway, createTinfoilAI, serializeSessionRecoveryToken, deserializeSessionRecoveryToken, type SessionRecoveryToken } from 'tinfoil';
import { Verifier, Verification, type VerifierOptions, type Measurement } from '@tinfoilsh/verifier';
import { UnverifiedClient } from 'tinfoil/unsafe';
const options: VerifierOptions = { pinnedRegisters: { type: 'tdx', mrtd: '00'.repeat(48) } };
const verifier = new Verifier(options);
const verified: Promise<Verification> = verifier.verifyDocumentV3At(new Uint8Array(), new Uint8Array(32), 'owner/name', new Date());
void verified.then(value => { const m: Measurement = value.enclaveMeasurement; return [m, value.freshnessExpiresAt, value.hpkePublicKey()]; });
const direct = new SecureClient({ enclaveURL: 'https://example.test', configRepo: 'tinfoilsh/example' });
const client = new TinfoilAI({ apiKey: 'test' });
const request: TinfoilAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming = { model: 'm', messages: [], response_format: { type: 'json_schema', json_schema: { name: 'record', strict: true, schema: { type: 'object' } } } };
client.chat.completions.create(request).withResponse();
client.responses; client.decisions; client.batches;
new Client(); new Gateway('https://gateway.test'); void direct.inspect(); void UnverifiedClient;
const token: SessionRecoveryToken = { exportedSecret: new Uint8Array(), requestEnc: new Uint8Array() };
deserializeSessionRecoveryToken(serializeSessionRecoveryToken(token));
void createTinfoilAI('test', { gateway: { url: 'https://gateway.test' } }).then(provider => provider('model'));
// @ts-expect-error fixture roots are not public configuration
new Verifier({ sigstoreRoot: {} });
// @ts-expect-error successful result construction is private
new Verification();
// @ts-expect-error fixture composition is not exported
import { createVerifierForConformance } from '@tinfoilsh/verifier';
`,
  );
  await writeFile(
    join(directory, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2020",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        lib: ["ES2020", "DOM"],
        strict: true,
        noEmit: true,
        skipLibCheck: false,
        types: [],
      },
      files: ["public.ts"],
    }),
  );
  run(
    process.execPath,
    [join(root, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"],
    directory,
  );
  console.log(
    "Actual tarball contents, Node/browser imports, public TypeScript, provider and serialization checks passed.",
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
