/**
 * Where an OpenAI-compatible client over an attested HTTP client sends its
 * requests: the API path joined under the HTTP client's route. This module
 * imports no API library, so the OpenAI client and the AI SDK provider
 * share it.
 */
import { ConfigurationError } from "../errors.js";

/** Which route an attested HTTP client takes. */
export type Route = "enclave" | "router" | "gateway";

const routes = new WeakMap<object, Route>();

/** @internal Records that a client's factory constructed it, and its route. */
export function registerRoute(client: object, route: Route): void {
  routes.set(client, route);
}

/** @internal The route of a client that a factory constructed; undefined for anything else. */
export function routeOf(client: unknown): Route | undefined {
  return typeof client === "object" && client !== null ? routes.get(client) : undefined;
}

/** The API path that an unset `apiPath` selects. */
export const DEFAULT_API_PATH = "/v1/";

/**
 * The characters that a path may hold as it is written in a URL: RFC 3986
 * `pchar` and `/`, with `%` only as the start of an escape. Anything else,
 * such as a backslash, a space or a control character, would be rewritten
 * by the URL parser, which could turn it into a separator or a dot segment.
 */
const PATH_CHARS = /^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})*$/;

/**
 * `segment` with each escape replaced by the byte that it encodes, one
 * character per byte, so that an escape of any byte decodes, whether or not
 * the bytes are valid UTF-8. The caller has checked that every `%` starts a
 * well-formed escape.
 */
function decodeBytes(segment: string): string {
  return segment.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

/**
 * Requires a non-empty RFC 3986 `path-absolute` of path characters and well-formed
 * `%XX` escapes, and refuses a leading `//`, a query, a fragment, a "." or
 * ".." segment, percent-encoded or not, and an encoded slash or backslash,
 * so that it can only name a path under its root. Any other well-formed
 * escape is accepted, including one of a byte that isn't valid UTF-8.
 */
export function validateAPIPath(apiPath: string): void {
  if (typeof apiPath !== "string") throw new ConfigurationError("invalid API path: it must be a string, such as /v1/");
  if (apiPath === "") throw new ConfigurationError("invalid API path: it is empty; leave apiPath out for the default /v1/");
  const invalid = (why: string): ConfigurationError => new ConfigurationError(`invalid API path ${JSON.stringify(apiPath)}: ${why}`);
  if (!apiPath.startsWith("/") || apiPath.startsWith("//")) throw invalid("it must be an absolute path, such as /v1/");
  if (apiPath.includes("?") || apiPath.includes("#")) throw invalid("it must not carry a query or a fragment");
  if (!PATH_CHARS.test(apiPath)) throw invalid("it must consist only of RFC 3986 path characters and well-formed percent escapes");
  for (const segment of apiPath.split("/")) {
    const decoded = decodeBytes(segment);
    if (decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\")) {
      throw invalid('it must not contain a "." or ".." segment or an encoded slash or backslash');
    }
  }
}

/**
 * `apiPath`, or {@link DEFAULT_API_PATH} when it is undefined, joined under
 * `root`, a proxy URL, an origin or a gateway URL, whether or not `root`
 * ends with a slash. An empty `apiPath` is a {@link ConfigurationError}.
 * The result ends with a slash, so that request paths join under it.
 */
export function joinAPIPath(root: string, apiPath: string | undefined): string {
  const path = apiPath ?? DEFAULT_API_PATH;
  validateAPIPath(path);
  const joined = (root.endsWith("/") ? root.slice(0, -1) : root) + path;
  return joined.endsWith("/") ? joined : `${joined}/`;
}

/**
 * The base URL of an OpenAI-compatible client over `httpClient`: the API
 * path joined under the HTTP client's base URL, which is the EHBP proxy or
 * the enclave's origin, or the gateway's URL. Anything other than a client
 * that one of the SDK's factories constructed is refused.
 */
export function apiBaseURL(httpClient: unknown, apiPath: string | undefined): string {
  const route = routeOf(httpClient);
  if (route === undefined) {
    const what = httpClient === null ? "null" : typeof httpClient === "object" ? (httpClient.constructor?.name ?? "an object") : typeof httpClient;
    throw new ConfigurationError(`the HTTP client must be an EnclaveHTTPClient, RouterHTTPClient or GatewayHTTPClient from its factory, not ${what}`);
  }
  return joinAPIPath((httpClient as { readonly baseURL: string }).baseURL, apiPath);
}
