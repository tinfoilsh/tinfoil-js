import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';
import { createPinnedTlsFetch } from '../src/pinned-tls-fetch.js';
import { AttestationError, ConfigurationError } from '../src/errors.js';

const cert = readFileSync(new URL('./fixtures/ws-test-cert.pem', import.meta.url), 'utf8');
const key = readFileSync(new URL('./fixtures/ws-test-key.pem', import.meta.url), 'utf8');
const fingerprint = createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
let originalRoots: string[];
const servers: Server[] = [];

beforeAll(() => { originalRoots = getCACertificates('default'); setDefaultCACertificates([...originalRoots, cert]); });
afterAll(() => setDefaultCACertificates(originalRoots));
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => {
    server.closeAllConnections(); server.close(() => resolve());
  })));
});

async function serve(handler: (request: IncomingMessage, response: ServerResponse) => void): Promise<string> {
  const server = createServer({ cert, key }, handler); servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  return `https://127.0.0.1:${address.port}`;
}
function echo(request: IncomingMessage, response: ServerResponse) {
  const body: Buffer[] = [];
  request.on('data', chunk => body.push(chunk));
  request.on('end', () => {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ method: request.method, headers: request.headers, path: request.url, body: Buffer.concat(body).toString() }));
  });
}

describe('real pinned HTTPS transport', () => {
  it('checks the actual peer key and preserves Request/init precedence', async () => {
    const origin = await serve(echo);
    const fetch = await createPinnedTlsFetch(origin + '/v1', fingerprint);
    const request = new Request(origin + '/v1/chat/completions?x=1', { method: 'POST', headers: { 'x-source': 'request' }, body: 'old' });
    const response = await fetch(request, { method: 'PUT', headers: { 'x-source': 'init', authorization: 'Bearer test' }, body: 'new' });
    expect(response.url).toBe(origin + '/v1/chat/completions?x=1');
    expect(await response.json()).toMatchObject({ method: 'PUT', path: '/v1/chat/completions?x=1', body: 'new', headers: { 'x-source': 'init', authorization: 'Bearer test' } });
  });
  it('rejects a different pin before HTTP payload, including after a valid connection', async () => {
    let requests = 0;
    const origin = await serve((_request, response) => { requests++; response.end('accepted'); });
    const good = await createPinnedTlsFetch(origin, fingerprint);
    expect(await (await good(origin)).text()).toBe('accepted');
    const wrong = await createPinnedTlsFetch(origin, '01'.repeat(32));
    await expect(wrong(origin, { method: 'POST', headers: { authorization: 'Bearer must-not-send' }, body: 'secret' })).rejects.toBeInstanceOf(AttestationError);
    expect(requests).toBe(1);
    expect(await (await good(origin)).text()).toBe('accepted'); expect(requests).toBe(2);
  });
  it('rejects plaintext and another origin before sending credentials', async () => {
    let requests = 0;
    const origin = await serve((_request, response) => { requests++; response.end(); });
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    await expect(fetch(origin.replace('https:', 'http:'), { headers: { authorization: 'Bearer secret' } })).rejects.toBeInstanceOf(ConfigurationError);
    await expect(fetch('https://example.com/', { headers: { authorization: 'Bearer secret' } })).rejects.toBeInstanceOf(ConfigurationError);
    expect(requests).toBe(0);
  });
  it('blocks cross-origin redirects without forwarding headers or body', async () => {
    let forwarded = 0;
    const target = await serve((_request, response) => { forwarded++; response.end(); });
    const origin = await serve((_request, response) => { response.writeHead(307, { location: target + '/sink' }); response.end('redirect'); });
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    await expect(fetch(origin, { method: 'POST', headers: { authorization: 'Bearer secret' }, body: 'payload' })).rejects.toBeInstanceOf(ConfigurationError);
    expect(forwarded).toBe(0);
  });
  it('preserves bytes on same-origin 307 and supports manual redirects', async () => {
    const origin = await serve((request, response) => {
      if (request.url === '/start') { response.writeHead(307, { location: '/echo' }); response.end(); }
      else echo(request, response);
    });
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    const body = '{"large":9007199254740993,"space":  true}';
    expect(await (await fetch(origin + '/start', { method: 'POST', body })).json()).toMatchObject({ method: 'POST', body, path: '/echo' });
    const manual = await fetch(origin + '/start', { redirect: 'manual' });
    expect(manual.status).toBe(307); await manual.body?.cancel();
  });
  it('converts POST to GET on 303 and removes body headers', async () => {
    const origin = await serve((request, response) => {
      if (request.url === '/start') { response.writeHead(303, { location: '/echo' }); response.end(); }
      else echo(request, response);
    });
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    const result = await (await fetch(origin + '/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
    expect(result).toMatchObject({ method: 'GET', body: '' }); expect(result.headers['content-type']).toBeUndefined();
  });
  it('serializes FormData through the Fetch Request body', async () => {
    const origin = await serve(echo);
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    const form = new FormData(); form.set('model', 'test-model'); form.set('file', new Blob(['file bytes']), 'upload.txt');
    const result = await (await fetch(origin, { method: 'POST', body: form })).json();
    expect(result.headers['content-type']).toMatch(/^multipart\/form-data; boundary=/);
    expect(result.body).toContain('name="model"'); expect(result.body).toContain('file bytes');
  });
  it('keeps response streaming abortable after headers arrive', async () => {
    const origin = await serve((_request, response) => { response.writeHead(200); response.write('first'); });
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    const controller = new AbortController();
    const response = await fetch(origin, { signal: controller.signal });
    const reader = response.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('first');
    controller.abort(new DOMException('cancel stream', 'AbortError'));
    await expect(reader.read()).rejects.toThrow();
  });
  it('honors cancellation before opening a socket and bodyless response semantics', async () => {
    let requests = 0;
    const origin = await serve((_request, response) => { requests++; response.writeHead(204); response.end(); });
    const fetch = await createPinnedTlsFetch(origin, fingerprint);
    const controller = new AbortController(); controller.abort();
    await expect(fetch(origin, { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
    expect(requests).toBe(0);
    const response = await fetch(origin);
    expect(response.status).toBe(204); expect(response.body).toBeNull();
  });
});
