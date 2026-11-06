/**
 * The published type declarations, as `npm run build` emits them: only the
 * files the entries reach, nothing marked internal, no seam or in-package
 * helper, no internal type named in a public signature, and the clients
 * with private constructors. The checks are shared with the verifier
 * package; this file supplies the client's data.
 */
import { fileURLToPath } from "node:url";
import { describePublishedDeclarations } from "../../../test-support/declarations.js";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));

describePublishedDeclarations({
  dist,
  entries: ["index.d.ts", "index.browser.d.ts", "ai-sdk.d.ts", "unsafe.d.ts"].map((e) => `${dist}${e}`),
  forbidden: [
    /@internal/,
    /KeyedTransport/,
    /GatewayTransport/,
    /Seams\b/,
    /\bTOKEN\b/,
    /create(Enclave|Router|Gateway)HTTPClient/,
    /createUnverifiedClient/,
    /createTinfoilClient/,
    /create(Enclave|Router|Gateway)OpenAIClient/,
    /createTinfoilProvider/,
    /openAIURLOf|setOpenAIURL|attestedFetch|checkEnclaveOptions|checkUnverifiedOptions|modeFor|resolveTransportMode/,
  ],
  privatelyConstructed: {
    EnclaveHTTPClient: "enclave-client.d.ts",
    RouterHTTPClient: "router-client.d.ts",
    GatewayHTTPClient: "gateway-client.d.ts",
    TinfoilClient: "openai-client.d.ts",
    EnclaveOpenAIClient: "openai-client.d.ts",
    RouterOpenAIClient: "openai-client.d.ts",
    GatewayOpenAIClient: "openai-client.d.ts",
    UnverifiedClient: "internal/unsafe-client.d.ts",
  },
});
