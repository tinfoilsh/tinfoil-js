/// <reference types="vitest" />
import { defineConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";
import { browserField } from "./vite.config.browser.js";

/**
 * The live browser lane: the browser build in Chromium against the live
 * service. A page has no process environment, so the lane's gate and the
 * credential are compiled into the bundle. Web security is disabled so the
 * page can reach the service's origins, as a deployed page would through
 * its own origin's CORS policy.
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
