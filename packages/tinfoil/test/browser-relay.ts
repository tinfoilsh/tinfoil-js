import { createServer, type Server } from "node:http";
import type { Plugin } from "vite";
import { Identity, PROTOCOL, HPKE_REQUEST_INFO, EXPORT_LABEL, EXPORT_LENGTH, bytesToHex, hexToBytes, deriveResponseKeys, encryptChunk } from "ehbp";
import { CipherSuite, KDF_HKDF_SHA256, AEAD_AES_256_GCM } from "hpke";
import { KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
/** Local cross-origin relay for browser CORS and encrypted-body tests. */
export function browserRelay(): Plugin {
  let server: Server;
  let origin = "";
  let publicKey = "";
  const sessions = new Map<string, { closed: boolean; plaintext: string }>();
  return {
    name: "tinfoil-browser-relay",
    resolveId(id) { if (id === "virtual:tinfoil-browser-relay") return "\0tinfoil-browser-relay"; },
    load(id) { if (id === "\0tinfoil-browser-relay") return `export default ${JSON.stringify(origin)}; export const publicKey = ${JSON.stringify(publicKey)};`; },
    closeBundle() { if (server) { server.closeAllConnections(); server.close(); } },
    async configureServer(vite) {
      const identity = await Identity.generate(); publicKey = await identity.getPublicKeyHex();
      const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
      server = createServer((request, response) => {
        if (request.url !== "/blocked") response.setHeader("access-control-allow-origin", request.headers.origin ?? "*");
        response.setHeader("access-control-allow-methods", "POST, GET, OPTIONS");
        response.setHeader("access-control-allow-headers", request.headers["access-control-request-headers"] ?? "*");
        if (request.method === "OPTIONS") { response.writeHead(204); response.end(); return; }
        const url = new URL(request.url!, "http://test-relay");
        if (url.pathname === "/session-state") { response.setHeader("content-type", "application/json"); response.end(JSON.stringify(sessions.get(url.searchParams.get("id")!) ?? null)); return; }
        const chunks: Buffer[] = [];
        request.on("data", chunk => chunks.push(chunk));
        request.on("end", () => {
          const body = Buffer.concat(chunks);
          if (url.pathname === "/session-stream") {
            void (async () => {
              const requestEnc = hexToBytes(String(request.headers[PROTOCOL.ENCAPSULATED_KEY_HEADER.toLowerCase()]));
              const context = await suite.SetupRecipient(identity.getPrivateKey(), requestEnc, { info: new TextEncoder().encode(HPKE_REQUEST_INFO) });
              const plaintext = await context.Open(body.subarray(4));
              const state = { closed: false, plaintext: new TextDecoder().decode(plaintext) };
              sessions.set(url.searchParams.get("id")!, state); response.on("close", () => { state.closed = true; });
              const secret = new Uint8Array(await context.Export(new TextEncoder().encode(EXPORT_LABEL), EXPORT_LENGTH));
              const nonce = crypto.getRandomValues(new Uint8Array(32));
              const keys = await deriveResponseKeys(secret, requestEnc, nonce);
              const encrypted = await encryptChunk(keys, 0, new TextEncoder().encode("authenticated first frame"));
              const frame = Buffer.alloc(4 + encrypted.length); frame.writeUInt32BE(encrypted.length); frame.set(encrypted, 4);
              response.setHeader(PROTOCOL.RESPONSE_NONCE_HEADER, bytesToHex(nonce));
              response.setHeader("access-control-expose-headers", PROTOCOL.RESPONSE_NONCE_HEADER);
              response.setHeader("content-type", "application/octet-stream"); response.writeHead(200); response.write(frame);
              // Remain open until browser cancellation closes the real response socket.
            })().catch(error => { if (!response.headersSent) response.writeHead(500); response.end(String(error)); });
            return;
          }
          response.setHeader("content-type", "application/json");
          response.setHeader("x-tinfoil-seal", "next-enclave.test");
          if (request.url === "/allowed") response.setHeader("access-control-expose-headers", "X-Tinfoil-Seal, Ehbp-Response-Nonce");
          response.writeHead(412);
          response.end(JSON.stringify({ model: request.headers["x-tinfoil-model"], seal: request.headers["x-tinfoil-seal"], enclave: request.headers["x-tinfoil-enclave-url"], private: !body.includes("secret browser prompt"), size: body.length }));
        });
      });
      await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
      server.unref();
      origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      vite.httpServer?.once("close", () => { server.closeAllConnections(); server.close(); });
    },
  };
}
