/**
 * The credential rule the OpenAI clients and the AI SDK provider share: a
 * long-lived API key is accepted only where the runtime is a server. A page
 * or a worker holds a `bearerToken` instead, such as a short-lived token
 * from the application's own sign-in. The runtime is identified as the
 * transport mode's default is: Node and Bun are servers; the browser build
 * treats nothing as one.
 */
import { ConfigurationError } from "../errors.js";
import { isServerRuntime, type RuntimeGlobals } from "./platform.js";

/** Why an API key is refused outside a server. */
export const API_KEY_NEEDS_SERVER = "an apiKey is a long-lived credential that belongs on a server; in a browser, give a bearerToken such as a short-lived token from the application's own sign-in";

/**
 * Refuses a given `apiKey` where the runtime isn't a server, before any
 * network I/O. An empty or absent key passes: it is no credential.
 */
export function checkAPIKeyRuntime(apiKey: unknown, globals?: RuntimeGlobals): void {
  if (apiKey === undefined || apiKey === null || apiKey === "") return;
  if (!isServerRuntime(globals)) throw new ConfigurationError(API_KEY_NEEDS_SERVER);
}

/**
 * @internal Resolves the credential a client sends on a connection opened
 * outside its request loop, such as a realtime session, when that
 * connection is opened: `null` when the client holds none.
 */
export type CredentialResolver = () => string | null | Promise<string | null>;

const credentials = new WeakMap<object, CredentialResolver>();

/** @internal Records how a client its factory constructed, a clone included, resolves its credential. */
export function registerCredential(client: object, resolve: CredentialResolver): void {
  credentials.set(client, resolve);
}

/** @internal The resolver a factory registered for `client`; anything else is refused. */
export function credentialOf(client: object): CredentialResolver {
  const found = credentials.get(client);
  if (found === undefined) throw new ConfigurationError("client was not created by its factory");
  return found;
}
