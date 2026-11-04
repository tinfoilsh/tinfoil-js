/**
 * WebSockets pinned to the attested TLS key. A WebSocket can't be sealed
 * the way an HTTP body can, so it is protected by connecting directly to the
 * enclave over TLS with the peer's certificate checked against the attested
 * key in the handshake, exactly as the TLS transport mode checks it. Node
 * connects through the `ws` client; Bun through its own WebSocket, whose
 * TLS settings take the same check. On either, nothing is sent before the
 * check passes, and a connection the runtime opened without running the
 * check is closed before it is handed out. Node and Bun only: the browser
 * entry maps this module to a stub.
 */
import type * as WS from "ws";
import { isBun } from "../../../env.js";
import { ConfigurationError } from "../../errors.js";
import type { PinnedWebSocket, WebSocketOptions } from "../../options.js";
import { identityCheck, type IdentityCheck } from "./pin.js";
import type { TLSOptions } from "./tls.js";
import { PeerLacksKeyError } from "./transport.js";

/** The `ws` settings that would change which peer is connected to, or how its certificate is checked; a caller's values are dropped. */
const RESERVED_WS_OPTIONS = ["agent", "createConnection", "followRedirects", "session", "socket", "servername", "pskCallback", "checkServerIdentity", "rejectUnauthorized", "ca", "headers", "protocol"] as const;

/** `wsOptions` without the reserved settings. */
export function allowedWsOptions(wsOptions: Readonly<Record<string, unknown>> | undefined): Record<string, unknown> {
  const allowed: Record<string, unknown> = { ...wsOptions };
  for (const key of RESERVED_WS_OPTIONS) delete allowed[key];
  return allowed;
}

/**
 * `ws` client settings that pin the connection to `key`, for wiring a pinned
 * WebSocket into a library that builds its own: the normal certificate check
 * stays on, and the identity check adds the pin. Node only: Bun's `ws` is a
 * substitute whose handling of these settings is not relied on.
 */
export async function pinnedWsClientOptions(key: string, tls: TLSOptions): Promise<WS.ClientOptions> {
  if (isBun()) throw new ConfigurationError("`ws` client settings can't pin a connection on Bun; use createWebSocket, which pins through Bun's own WebSocket");
  const check = await identityCheck(key);
  return {
    rejectUnauthorized: true,
    ca: tls.ca === undefined ? undefined : (Buffer.from(tls.ca) as WS.CertMeta),
    agent: undefined,
    createConnection: undefined,
    followRedirects: false,
    // The library declares the check's result as a boolean; the runtime takes `Error | undefined`, so a boolean would invert it.
    checkServerIdentity: check as unknown as NonNullable<WS.ClientOptions["checkServerIdentity"]>,
  };
}

/** Opens a WebSocket to `url` (wss) pinned to `key`, in the CONNECTING state. */
export async function openPinnedWebSocket(url: URL, key: string, options: WebSocketOptions, tls: TLSOptions): Promise<PinnedWebSocket> {
  if (url.protocol !== "wss:") throw new ConfigurationError(`a pinned WebSocket requires a wss:// URL, got ${JSON.stringify(url.toString())}`);
  const protocols = options.protocols === undefined ? undefined : typeof options.protocols === "string" ? [options.protocols] : [...options.protocols];
  return isBun() ? openOnBun(url, key, protocols, options, tls) : openOnNode(url, key, protocols, options, tls);
}

async function openOnNode(url: URL, key: string, protocols: string[] | undefined, options: WebSocketOptions, tls: TLSOptions): Promise<PinnedWebSocket> {
  const [{ WebSocket }, pinned] = await Promise.all([import("ws"), pinnedWsClientOptions(key, tls)]);
  const socket = new WebSocket(url, protocols, {
    ...allowedWsOptions(options.wsOptions),
    headers: { ...options.headers },
    ...pinned,
  });
  return socket as unknown as PinnedWebSocket;
}

/** Bun's WebSocket constructor settings, which its typings don't cover. */
interface BunWebSocketInit {
  readonly protocols?: string[];
  readonly headers?: Record<string, string>;
  readonly tls?: { readonly ca?: string | Uint8Array; readonly checkServerIdentity?: IdentityCheck };
}

async function openOnBun(url: URL, key: string, protocols: string[] | undefined, options: WebSocketOptions, tls: TLSOptions): Promise<PinnedWebSocket> {
  const check = await identityCheck(key);
  let checked = false;
  const init: BunWebSocketInit = {
    protocols,
    headers: { ...options.headers },
    tls: {
      ca: tls.ca,
      checkServerIdentity: (host, cert) => {
        checked = true;
        return check(host, cert);
      },
    },
  };
  const socket = new (WebSocket as unknown as new (url: URL, init: BunWebSocketInit) => PinnedWebSocket & EventTarget)(url, init);
  // A runtime that opened the connection without consulting the check never pinned it: close before anything is sent.
  socket.addEventListener(
    "open",
    () => {
      if (checked) return;
      socket.close(1008, "connection was not pinned to the attested key");
      socket.dispatchEvent(new ErrorEvent("error", { error: new PeerLacksKeyError("the runtime opened the connection without checking the peer's certificate") }));
    },
    { once: true },
  );
  return socket;
}
