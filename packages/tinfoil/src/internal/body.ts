/**
 * Reads a request body into memory for the layers that inspect or rewrite
 * one before it is sent, bounded in size and stopped by the caller's abort.
 */
import { ConfigurationError } from "../errors.js";

/**
 * The body's bytes, within `limit`; a larger body is a {@link ConfigurationError}
 * naming `what`. An abort of `signal` cancels the stream, stops the read and
 * rejects with the signal's reason. A stream body is consumed; every other
 * kind is copied.
 */
export async function readAll(body: BodyInit, limit: number, what: string, signal?: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  signal?.throwIfAborted();
  if (typeof body === "string") {
    const encoded = new TextEncoder().encode(body) as Uint8Array<ArrayBuffer>;
    if (encoded.length > limit) throw new ConfigurationError(`reading ${what}: body exceeds ${limit} bytes`);
    return encoded;
  }
  const stream: ReadableStream<Uint8Array> | null = body instanceof ReadableStream ? body : new Response(body).body;
  if (stream === null) return new Uint8Array();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  // One listener serves the whole read: it cancels the stream, which settles
  // a pending read, and rejects the race for a source whose cancel stalls.
  // The listener is removed once the read ends, so a long-lived signal keeps
  // nothing of a completed read.
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    if (signal === undefined) return;
    onAbort = () => {
      reject(signal.reason);
      void reader.cancel(signal.reason).catch(() => {});
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
  // An abort between two reads rejects with nothing racing it yet.
  aborted.catch(() => {});
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), aborted]);
      signal?.throwIfAborted();
      if (done) break;
      total += value.length;
      if (total > limit) {
        // Not awaited: a source whose cancel stalls or fails must not hide the size error.
        void reader.cancel().catch(() => {});
        throw new ConfigurationError(`reading ${what}: body exceeds ${limit} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    if (onAbort !== undefined) signal?.removeEventListener("abort", onAbort);
  }
  const out = new Uint8Array(new ArrayBuffer(total));
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}
