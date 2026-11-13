/**
 * The OpenAI options that would route requests away from the attested
 * transport, each with a value that sets it, for the tests that check that
 * the clients refuse them.
 */
import type OpenAI from "openai";
import { expect } from "vitest";
import { ConfigurationError } from "../../src/errors.js";

/** Each refused option with a value that sets it; the values pass no type check, as an untyped caller's wouldn't. */
export const FORBIDDEN_TRANSPORT_OPTIONS: Readonly<Record<string, unknown>> = {
  dataResidency: "eu",
  provider: { baseURL: "https://provider.example/v1" },
  workloadIdentity: { clientId: "id", identityProviderId: "idp", serviceAccountId: "sa" },
  credential: { kind: "x509" },
  x509Transport: { fetch: async () => new Response("intercepted") },
};

/** The error a refused option gives, which names it. */
export function refusal(key: string): RegExp {
  return new RegExp(`the ${key} option is not supported: the Tinfoil client owns the transport and base URL`);
}

/**
 * Expects `withOptions` to refuse each option with a {@link ConfigurationError}
 * naming it, and to accept one held as `undefined` or `null`, which is unset.
 */
export function expectWithOptionsRefusesTransportOptions(client: OpenAI): void {
  for (const [key, value] of Object.entries(FORBIDDEN_TRANSPORT_OPTIONS)) {
    expect(() => client.withOptions({ [key]: value } as never)).toThrow(ConfigurationError);
    expect(() => client.withOptions({ [key]: value } as never)).toThrow(refusal(key));
    expect(client.withOptions({ [key]: undefined } as never).baseURL).toBe(client.baseURL);
    expect(client.withOptions({ [key]: null } as never).baseURL).toBe(client.baseURL);
  }
}
