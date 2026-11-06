/**
 * A local EHBP server for tests: the EHBP peer behind an HTTP listener,
 * writing each response chunk as its own frame as the route yields it.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { PROTOCOL, type Identity } from "ehbp";
import { createEhbpPeer, type Reply, type Seen } from "./ehbp-peer.js";

export { paced, type Reply, type Seen } from "./ehbp-peer.js";

export interface EhbpServer {
  readonly origin: string;
  readonly publicKeyHex: string;
  readonly identity: Identity;
  readonly seen: Seen[];
  close(): Promise<void>;
}

export async function startEhbpServer(route: (seen: Seen) => Reply | Promise<Reply>): Promise<EhbpServer> {
  const peer = await createEhbpPeer(route);

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      void (async () => {
        const encHex = req.headers[PROTOCOL.ENCAPSULATED_KEY_HEADER.toLowerCase()];
        const produced = await peer.respond(req.method ?? "", req.url ?? "", req.headers, new Uint8Array(Buffer.concat(chunks)), typeof encHex === "string" ? encHex : undefined);
        res.writeHead(produced.status, produced.headers);
        for await (const chunk of produced.chunks) res.write(Buffer.from(chunk));
        res.end();
      })().catch((err: unknown) => {
        // Once headers are out, the client already has a status; cut the connection instead.
        if (res.headersSent) {
          res.destroy(err instanceof Error ? err : new Error(String(err)));
          return;
        }
        res.writeHead(500, { "content-type": "text/plain" });
        res.end(String(err));
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    origin,
    publicKeyHex: peer.publicKeyHex,
    identity: peer.identity,
    seen: peer.seen,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
