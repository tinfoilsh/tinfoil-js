/// <reference types="vitest" />
import { defineConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";

/**
 * The live browser lane: the verifier's root entry in Chromium against the
 * live service. A page has no process environment, so the lane's gate is
 * compiled into the bundle. Web security is disabled so the page can fetch
 * the attestation document from the service's origin, as a deployed page
 * would through its own origin's CORS policy.
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
      instances: [
        {
          browser: "chromium",
          launch: {
            args: ["--disable-web-security", "--disable-features=IsolateOrigins,site-per-process"],
          },
        },
      ],
    },
  },
});
