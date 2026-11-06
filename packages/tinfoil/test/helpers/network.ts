/**
 * A network fetch for tests, standing in for a native HTTP bridge or a
 * relay given through the `fetch` option: it records each request as it
 * would leave the machine, with its body buffered, and forwards it with
 * the fetch that it was built over.
 */
import type { Fetch } from "../../src/options.js";

/** One request as the network saw it: the URL, the headers, and the body's bytes decoded as text. */
export interface SeenByNetwork {
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: string;
}

export function recordingFetch(send: Fetch): { fetch: Fetch; seen: SeenByNetwork[] } {
  const seen: SeenByNetwork[] = [];
  return {
    seen,
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const body = new Uint8Array(await request.arrayBuffer());
      seen.push({ url: request.url, method: request.method, headers: request.headers, body: new TextDecoder().decode(body) });
      return send(request.url, { method: request.method, headers: request.headers, body: body.byteLength === 0 ? null : body, signal: request.signal });
    },
  };
}
