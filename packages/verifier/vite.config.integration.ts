/// <reference types="vitest" />
import { defineConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";

/**
 * The live browser lane: the verifier's root entry in Chromium against the
 * live service. A page has no process environment, so the lane's gate is
 * compiled into the bundle. The browser runs with its same-origin policy
 * intact: the page is served from a localhost origin and fetches the
 * attestation document through the service's CORS policy, as a deployed
 * page does, so a service that stopped allowing a page's requests fails
 * here.
 */
export default defineConfig({
  define: {
    "process.env.RUN_TINFOIL_INTEGRATION": JSON.stringify(process.env.RUN_TINFOIL_INTEGRATION ?? ""),
  },
  test: {
    include: ["test/*.browser.integration.test.ts"],
    testTimeout: 120_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }],
    },
  },
});
