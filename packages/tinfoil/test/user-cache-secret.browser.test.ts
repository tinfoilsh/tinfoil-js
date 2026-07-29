import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveUserCacheSecret } from "../src/user-cache-secret";

describe("user cache secret (browser)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("silently uses a stable in-memory secret", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const first = await resolveUserCacheSecret();

    expect(first).toMatch(/^[0-9a-f]{64}$/);
    await expect(resolveUserCacheSecret()).resolves.toBe(first);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
