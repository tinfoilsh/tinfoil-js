/// <reference types="vitest" />
import { defineConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";
import { browserField } from "./vite.config.browser.js";

/**
 * The live browser lane: the browser build in Chromium against the live
 * service. A page has no process environment, so the lane's gate and the
 * credential are compiled into the bundle. The browser runs with its
 * same-origin policy intact: the page is served from a localhost origin and
 * reaches the service's origins through their CORS policy, as a deployed
 * page does, so a service that stopped allowing a page's requests fails
 * here.
 */
export default defineConfig({
  plugins: [browserField()],
  optimizeDeps: {
    include: ["openai", "ai", "@ai-sdk/openai-compatible"],
  },
  define: {
    "process.env.RUN_TINFOIL_INTEGRATION": JSON.stringify(process.env.RUN_TINFOIL_INTEGRATION ?? ""),
    "process.env.TINFOIL_API_KEY": JSON.stringify(process.env.TINFOIL_API_KEY ?? ""),
  },
  test: {
    include: ["test/*.browser.integration.test.ts"],
    testTimeout: 180_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }],
    },
  },
});
