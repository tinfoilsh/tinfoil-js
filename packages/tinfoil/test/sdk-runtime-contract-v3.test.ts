import { describe, expect, it, vi } from "vitest";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { createHash, X509Certificate } from "node:crypto";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { WebSocketServer } from "ws";
import { Identity } from "ehbp";
const evidence = vi.hoisted(() => ({ fingerprint: "", hpke: "" }));
vi.mock("@tinfoilsh/verifier", async original => ({ ...await original<object>(), Verifier: class {
  async verify() { return { freshnessExpiresAt: new Date(Date.now() + 60_000), tlsPublicKeyFingerprint: () => evidence.fingerprint, hpkePublicKey: () => evidence.hpke }; }
} }));
vi.mock("../src/acquisition.js", async original => ({ ...await original<object>(), fetchAttestationDocument: async () => new Uint8Array([1]) }));
import { SecureClient } from "../src/secure-client.js";
import { Client } from "../src/client.js";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch.js";
import { AttestationError } from "../src/errors.js";
const cert = readFileSync(new URL("./fixtures/ws-test-cert.pem", import.meta.url));
const key = readFileSync(new URL("./fixtures/ws-test-key.pem", import.meta.url));
async function listen(server: import("node:http").Server) { await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)); return (server.address() as { port: number }).port; }
async function close(server: import("node:http").Server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
describe("runtime SDK channel contracts", () => {
  it("sends cache-shaped TLS requests without gateway routing headers on the actual socket", async () => {
    const roots = getCACertificates("default"); setDefaultCACertificates([...roots, cert.toString()]);
    evidence.fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
    const server = httpsServer({ cert, key }, (request, response) => {
      const chunks: Buffer[] = []; request.on("data", chunk => chunks.push(chunk));
      request.on("end", () => { response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ headers: request.headers, body: Buffer.concat(chunks).toString() })); });
    });
    const port = await listen(server);
    try {
      const client = new Client({ enclaveURL: `https://127.0.0.1:${port}`, configRepo: "tinfoilsh/workload", transport: "tls", userCacheSecret: "private-cache-secret" });
      const result = await (await client.fetch("/v1/chat/completions", { method: "POST", headers: { authorization: "Bearer synthetic", "content-type": "application/json" }, body: '{"model":"test","seed":9007199254740993}' })).json();
      expect(result.body).toContain("9007199254740993"); expect(result.body).toContain("private-cache-secret");
      expect(result.headers.authorization).toBe("Bearer synthetic");
      for (const header of ["x-tinfoil-model", "x-tinfoil-seal", "x-tinfoil-enclave-url", "x-tinfoil-cache-prefix"]) expect(result.headers).not.toHaveProperty(header);
      expect(Object.values(result.headers).join(" ")).not.toContain("private-cache-secret");
    } finally { await close(server); setDefaultCACertificates(roots); }
  });
  it("opens an actual pinned Node WSS connection directly despite an HTTP forwarding proxy", async () => {
    evidence.fingerprint = createHash("sha256").update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" })).digest("hex");
    evidence.hpke = await (await Identity.generate()).getPublicKeyHex();
    let proxyTraffic = 0, acceptedSockets = 0;
    const proxy = httpServer((_request, response) => { proxyTraffic++; response.end(); });
    proxy.on("upgrade", (_request, socket) => { proxyTraffic++; socket.destroy(); });
    const enclave = httpsServer({ cert, key });
    const wss = new WebSocketServer({ server: enclave });
    wss.on("connection", socket => { acceptedSockets++; socket.on("message", data => socket.send(data)); });
    const [proxyPort, enclavePort] = await Promise.all([listen(proxy), listen(enclave)]);
    try {
      const config = { enclaveURL: `https://localhost:${enclavePort}`, configRepo: "tinfoilsh/workload", baseURL: `http://127.0.0.1:${proxyPort}/v1/` };
      const client = new SecureClient(config);
      const socket = await client.createWebSocket("/v1/realtime", { wsOptions: { ca: cert, headers: { authorization: "Bearer synthetic" } } });
      await new Promise<void>((resolve, reject) => { socket.once("open", resolve); socket.once("error", reject); });
      const echoed = new Promise<string>(resolve => socket.once("message", data => resolve(data.toString())));
      socket.send("pinned direct traffic"); expect(await echoed).toBe("pinned direct traffic");
      socket.terminate();
      evidence.fingerprint = "00".repeat(32);
      const wrong = await new SecureClient(config).createWebSocket("/v1/realtime", { wsOptions: { ca: cert } });
      const rejection = await new Promise<Error>(resolve => wrong.once("error", resolve));
      expect(rejection).toBeInstanceOf(AttestationError); expect(acceptedSockets).toBe(1); expect(proxyTraffic).toBe(0);
    } finally { for (const socket of wss.clients) socket.terminate(); wss.close(); await Promise.all([close(proxy), close(enclave)]); }
  });
  it("reports Fetch's unsupported Expect header without sending a sealed request body", async () => {
    let requests = 0, continues = 0;
    const server = httpServer((_request, response) => { requests++; response.end(); });
    server.on("checkContinue", (_request, response) => { continues++; response.writeContinue(); response.end(); });
    const port = await listen(server);
    try {
      const transport = createEncryptedBodyFetch(`http://127.0.0.1:${port}`, await (await Identity.generate()).getPublicKeyHex());
      await expect(transport.fetch("/", { method: "POST", headers: { Expect: "100-continue" }, body: "private" })).rejects.toBeInstanceOf(TypeError);
      expect(requests).toBe(0); expect(continues).toBe(0);
    } finally { await close(server); }
  });
});
