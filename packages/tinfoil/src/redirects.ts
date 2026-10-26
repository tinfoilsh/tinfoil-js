import { ConfigurationError } from "./errors.js";
const statuses = new Set([301, 302, 303, 307, 308]);
/** Follow only redirects that preserve the configured credential-bearing origin. */
export async function boundRedirectFetch(request: Request, send: (request: Request) => Promise<Response>): Promise<Response> {
  const origin = new URL(request.url).origin;
  const policy = request.redirect;
  for (let count = 0; ; count++) {
    const replay = policy === "follow" ? request.clone() : undefined;
    let response: Response;
    try { response = await send(new Request(request, { ...requestOptions(request), redirect: "manual" })); }
    catch (error) { if (replay?.body) void replay.body.cancel().catch(() => {}); throw error; }
    if (response.type === "opaqueredirect" && policy !== "manual") {
      if (replay?.body) void replay.body.cancel().catch(() => {});
      await response.body?.cancel();
      throw new ConfigurationError("This runtime cannot inspect and authorize the application redirect");
    }
    if (!statuses.has(response.status) || policy === "manual") {
      if (replay?.body) void replay.body.cancel().catch(() => {});
      return response;
    }
    const location = response.headers.get("location");
    if (!location) {
      if (replay?.body) void replay.body.cancel().catch(() => {});
      return response;
    }
    await response.body?.cancel();
    if (policy === "error") throw new TypeError("Redirect encountered with redirect policy error");
    if (count >= 20) {
      if (replay?.body) void replay.body.cancel().catch(() => {});
      throw new TypeError("Too many redirects");
    }
    const next = new URL(location, request.url);
    if (next.origin !== origin || next.username || next.password) {
      if (replay?.body) void replay.body.cancel().catch(() => {});
      throw new ConfigurationError("Cross-origin application redirect rejected");
    }
    let method = request.method;
    const headers = new Headers(request.headers);
    let body = replay!.body;
    if (((response.status === 301 || response.status === 302) && method === "POST") || (response.status === 303 && method !== "GET" && method !== "HEAD")) {
      method = "GET"; body = null;
      for (const name of ["content-encoding", "content-language", "content-location", "content-type", "content-length"]) headers.delete(name);
      await replay!.body?.cancel();
    }
    request = new Request(next, { ...requestOptions(replay!), method, headers, body, duplex: "half" } as RequestInit);
  }
}
export function requestOptions(request: Request): RequestInit {
  return { method: request.method, headers: request.headers, signal: request.signal, credentials: request.credentials, cache: request.cache, redirect: request.redirect, mode: request.mode, integrity: request.integrity, referrer: request.referrer, referrerPolicy: request.referrerPolicy, keepalive: request.keepalive };
}
