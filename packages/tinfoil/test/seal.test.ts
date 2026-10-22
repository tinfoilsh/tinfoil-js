import { describe, it, expect, vi, afterEach } from "vitest";
import { Identity, Transport } from "ehbp";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch";
import { AttestationError, FetchError } from "../src/verifier";

const GATEWAY = "https://gateway.example.com";
const A = "a.example.com";
const B = "b.example.com";
const SEAL = "X-Tinfoil-Seal";
const ENCLAVE_URL = "X-Tinfoil-Enclave-Url";
const PATH = "/v1/chat/completions";

const post = (headers: Record<string, string> = {}): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json", ...headers },
  body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
});

/** A gateway that either answers, or re-routes with a 421 naming another enclave. */
function serve(routeTo: (seal: string) => string) {
  const sent: RequestInit[] = [];
  vi.spyOn(Transport.prototype, "request").mockImplementation(async (_input, init) => {
    sent.push(init!);
    const seal = new Headers(init?.headers).get(SEAL) ?? "";
    const target = routeTo(seal);
    return target === seal
      ? new Response(`ok from ${seal}`, { status: 200 })
      : new Response("re-seal", { status: 421, headers: { [SEAL]: target } });
  });
  return {
    sent,
    header: (name: string) => sent.map((init) => new Headers(init.headers).get(name)),
  };
}

/** A client sealed to A that will attest any of `hosts` the gateway routes it to. */
async function client(hosts: string[], withReseal = true) {
  const keys: Record<string, string> = {};
  for (const host of hosts) {
    keys[host] = await (await Identity.generate()).getPublicKeyHex();
  }
  const attested: string[] = [];
  const reseal = async (enclaveURL: string) => {
    const host = new URL(enclaveURL).host;
    attested.push(host);
    if (!keys[host]) throw new AttestationError(`no such enclave: ${host}`);
    return keys[host];
  };
  const transport = createEncryptedBodyFetch(
    GATEWAY,
    keys[A],
    `https://${A}`,
    "s1",
    withReseal ? reseal : undefined,
  );
  return { attested, transport };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("seal following", () => {
  it("re-seals to the enclave the gateway routed to, and stays there", async () => {
    const gw = serve(() => B);
    const { transport } = await client([A, B]);

    const response = await transport.fetch(PATH, post());
    await transport.fetch(PATH, post());

    expect(await response.text()).toBe(`ok from ${B}`);
    expect(gw.header(SEAL)).toEqual([A, B, B]);
    expect(gw.header(ENCLAVE_URL)).toEqual([`https://${A}`, `https://${B}`, `https://${B}`]);
    // The retry re-seals the same body rather than re-reading a consumed stream.
    expect(gw.sent[1].body).toBe(gw.sent[0].body);
  });

  it("attests each enclave once, however many requests race", async () => {
    let target = B;
    const gw = serve(() => target);
    const { attested, transport } = await client([A, B]);

    await transport.fetch(PATH, post());
    target = A;
    await transport.fetch(PATH, post());
    expect(gw.header(SEAL)).toEqual([A, B, B, A]);

    target = B;
    await Promise.all([transport.fetch(PATH, post()), transport.fetch(PATH, post())]);
    expect(attested).toEqual([B]);
  });

  it("refuses an enclave that fails verification", async () => {
    serve(() => B);
    const { transport } = await client([A]);

    await expect(transport.fetch(PATH, post())).rejects.toThrow(
      `gateway routed to enclave ${B}, which failed verification`,
    );
  });

  it("gives up on a gateway that never converges", async () => {
    const gw = serve((seal) => (seal === A ? B : A));
    const { transport } = await client([A, B]);

    await expect(transport.fetch(PATH, post())).rejects.toThrow(FetchError);
    expect(gw.header(SEAL)).toEqual([A, B, A, B]);
  });

  it("leaves the enclave's own answers alone", async () => {
    // Same status, no seal header: the enclave's own answer, not a re-route.
    vi.spyOn(Transport.prototype, "request").mockResolvedValue(
      new Response("misdirected", { status: 421 }),
    );
    const { attested, transport } = await client([A, B]);

    expect((await transport.fetch(PATH, post())).status).toBe(421);
    expect(attested).toEqual([]);
  });

  it("lets a caller pin the seal per request, without moving off A", async () => {
    const gw = serve((seal) => seal);
    const { attested, transport } = await client([A, B]);

    const response = await transport.fetch(PATH, post({ [SEAL]: B }));
    await transport.fetch(PATH, post());

    expect(await response.text()).toBe(`ok from ${B}`);
    expect(gw.header(SEAL)).toEqual([B, A]);
    expect(attested).toEqual([B]);
  });

  it("re-pins a caller's seal the gateway rejects", async () => {
    const gw = serve(() => A);
    const { transport } = await client([A, B]);

    const response = await transport.fetch(PATH, post({ [SEAL]: B }));

    expect(await response.text()).toBe(`ok from ${A}`);
    expect(gw.header(SEAL)).toEqual([B, A]);
  });

  it("does not follow without a way to attest the target", async () => {
    serve(() => B);
    const { transport } = await client([A, B], false);

    expect((await transport.fetch(PATH, post())).status).toBe(421);
  });
});
