import { mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { fetchRouters, fetchAttestationDocument, SecureClient, Gateway } from '../../tinfoil/dist/index.js';
import { randomNonce, Verifier } from '../../verifier/dist/index.js';

// Run after npm run build: node packages/conformance/scripts/live-sdk.mjs --browser
// Uses only public discovery, evidence, /v1/models and a nonexistent diagnostic route.
// Never loads credentials or invokes an inference route. Browser checks retain CORS.
const { values } = parseArgs({ options: {
  report: { type: 'string', default: 'artifacts/live-sdk-report.json' },
  browser: { type: 'boolean', default: false },
} });
const endpoints = Object.freeze({
  inference: 'https://inference.tinfoil.sh',
  gateway: 'https://inference-gateway.tinfoil.sh',
  discovery: 'https://atc.tinfoil.sh/routers',
  routerReference: 'tinfoilsh/confidential-model-router',
});
const report = {
  checkedAt: new Date().toISOString(), node: process.version, endpoints,
  credentialsUsed: false, billableInferenceRequested: false,
  results: [], boundaries: [],
};
function failure(error, depth = 0) {
  return { name: error?.name, layer: error?.layer, message: error?.message,
    ...(error?.cause && depth < 4 ? { cause: failure(error.cause, depth + 1) } : {}) };
}
async function attempt(name, operation) {
  try {
    const result = await operation();
    report.results.push({ name, ok: true, result });
    console.log(`${name}: completed`);
    return result;
  } catch (error) {
    report.results.push({ name, ok: false, error: failure(error) });
    console.log(`${name}: ${error.name}: ${error.message}`);
    return undefined;
  }
}
async function publicFetch(url, init = {}) {
  return fetch(url, { ...init, credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(30_000) });
}
async function consume(response, limit = 32 * 1024 * 1024) {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = []; let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      total += value.byteLength;
      if (total > limit) throw new Error(`Response exceeded ${limit} bytes`);
      chunks.push(value);
    }
    return Buffer.concat(chunks, total);
  } finally { await reader.cancel(); reader.releaseLock(); }
}
async function evidence(label, endpoint, reference, relayURL) {
  return attempt(`${label}-offline-verification`, async () => {
    const nonce = randomNonce();
    const bytes = await fetchAttestationDocument(endpoint, nonce, { relayURL });
    const value = await new Verifier().verify(bytes, nonce, reference);
    // Classify only bytes that have passed the public verifier. No archive is a trust input.
    const document = JSON.parse(new TextDecoder().decode(bytes));
    const collateral = document.collateral.map(({ id, format }) => ({ id, format }));
    return { endpoint, reference, bytes: bytes.length, collateral,
      profile: collateral.some(item => item.id === 'tinfoil-config') ? 'registry' : 'classic',
      expiry: value.freshnessExpiresAt?.toISOString(),
      hasTLS: Boolean(value.tlsPublicKeyFingerprint()), hasHPKE: Boolean(value.hpkePublicKey()) };
  });
}
async function channel(transport) {
  return attempt(`direct-${transport}-channel`, async () => {
    const client = new SecureClient({ enclaveURL: endpoints.inference, configRepo: endpoints.routerReference, transport });
    await client.ready();
    const response = await client.fetch(transport === 'tls' ? '/v1/models' : '/sdk-channel-validation-nonexistent', {
      signal: AbortSignal.timeout(30_000),
      ...(transport === 'ehbp' ? { method: 'POST', body: '{"channel_test":true}', headers: { 'content-type': 'application/json' } } : {}),
    });
    const responseNoncePresent = response.headers.has('ehbp-response-nonce');
    const body = await consume(response);
    return { status: response.status, responseBytes: body.length, responseNoncePresent,
      expiry: client.inspect()?.verification.freshnessExpiresAt?.toISOString(),
      responseAuthentication: transport === 'tls' ? 'pinned-tls-peer'
        : responseNoncePresent ? 'authenticated-ehbp-response'
          : 'nonce-less-diagnostic-only; not proof of authenticated EHBP response' };
  });
}
async function browserCors() {
  const { chromium, webkit } = await import('playwright');
  const server = createServer((_request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end('<!doctype html><title>Public SDK CORS check</title>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
      await attempt(`browser-${name}-cors`, async () => {
        const browser = await engine.launch({ headless: true,
          ...(name === 'webkit' && process.env.TINFOIL_TEST_WEBKIT_EXECUTABLE
            ? { executablePath: process.env.TINFOIL_TEST_WEBKIT_EXECUTABLE } : {}),
        });
        try {
          const page = await browser.newPage(); await page.goto(origin);
          const checks = await page.evaluate(async endpoints => {
            const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
            const checks = [];
            for (const [name, url] of [
              ['router-discovery', endpoints.discovery],
              ['gateway-catalog', `${endpoints.gateway}/catalog`],
              ['inference-document', `${endpoints.inference}/.well-known/tinfoil-attestation?nonce=${nonce}`],
            ]) {
              try {
                const response = await fetch(url, { credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(30_000),
                  headers: { 'Tinfoil-SDK': 'tinfoil-js', 'Tinfoil-SDK-Version': '2.0.0' } });
                checks.push({ name, ok: response.ok, status: response.status, bytes: (await response.arrayBuffer()).byteLength, type: response.type });
              } catch (error) { checks.push({ name, ok: false, error: { name: error.name, message: error.message } }); }
            }
            return checks;
          }, endpoints);
          const failed = checks.filter(check => !check.ok);
          for (const check of failed) report.boundaries.push({ scope: `live-browser-${name}-${check.name}`,
            reason: 'Actual browser fetch failed with browser security enabled; this probe cannot establish browser support for this endpoint.', detail: check });
          return { engine: name, version: browser.version(), checks, allRequestsSucceeded: failed.length === 0 };
        } finally { await browser.close(); }
      });
    }
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
async function main() {
  const routers = await attempt('router-discovery', () => fetchRouters());
  const catalog = await attempt('gateway-catalog', async () => {
    const response = await publicFetch(`${endpoints.gateway}/catalog`);
    const bytes = await consume(response);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const entries = JSON.parse(new TextDecoder().decode(bytes));
    return { entries, accessControlAllowOrigin: response.headers.get('access-control-allow-origin') };
  });
  await evidence('inference', endpoints.inference, endpoints.routerReference);
  if (routers?.length) await evidence('router', routers[0], endpoints.routerReference);
  await channel('tls'); await channel('ehbp');
  const selected = Object.entries(catalog?.entries ?? {}).find(([, entry]) =>
    entry && typeof entry.repo === 'string' && /^tinfoilsh\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(entry.repo) &&
    Array.isArray(entry.hosts) && entry.hosts.length && entry.hosts.every(host => typeof host === 'string' && !/[\s/?#@]/.test(host)));
  if (selected) {
    const [model, entry] = selected;
    await evidence('gateway-relay', `https://${entry.hosts[0]}`, entry.repo, endpoints.gateway);
    await attempt('gateway-ready', async () => {
      const gateway = new Gateway(`${endpoints.gateway}/v1/`);
      await gateway.ready(model);
      return { model, endpoint: gateway.inspect()?.endpoint, expiry: gateway.inspect()?.verification.freshnessExpiresAt?.toISOString() };
    });
  } else report.boundaries.push({ scope: 'live-gateway', reason: 'Catalog did not provide a usable model; no gateway readiness claim.' });
  await attempt('gateway-catalog-preflight', async () => {
    const response = await publicFetch(`${endpoints.gateway}/catalog`, { method: 'OPTIONS', headers: {
      origin: 'http://127.0.0.1', 'access-control-request-method': 'GET',
      'access-control-request-headers': 'tinfoil-sdk,tinfoil-sdk-version',
    } });
    const observation = { status: response.status, allowOrigin: response.headers.get('access-control-allow-origin'),
      allowHeaders: response.headers.get('access-control-allow-headers') };
    await response.body?.cancel(); return observation;
  });
  if (values.browser) await browserCors();
  else report.boundaries.push({ scope: 'live-browser', reason: 'Not executed; pass --browser to launch Chromium and WebKit with browser security enabled.' });
  if (!report.results.some(result => result.ok && result.result?.profile === 'registry')) report.boundaries.push({
    scope: 'live-registry', reason: 'No registry-profile endpoint was observed.',
  });
  if (!report.results.some(result => result.name === 'direct-ehbp-channel' && result.ok && result.result.responseNoncePresent)) report.boundaries.push({
    scope: 'live-authenticated-ehbp-response', reason: 'The no-credential diagnostic route did not return an authenticated EHBP response; local cryptographic transport tests are separate evidence.',
  });
  report.outcome = report.results.some(result => !result.ok) ? 'probe-failures' : report.boundaries.length ? 'completed-with-explicit-boundaries' : 'completed';
  const path = resolve(values.report); await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(report, null, 2) + '\n');
  console.log(`${report.outcome}; report: ${path}`);
  // Known missing deployment capabilities are recorded, never converted into successful checks.
  // An unavailable browser binary or failed readiness/verification is an execution failure.
  if (report.results.some(result => !result.ok)) process.exitCode = 1;
}
await main();
