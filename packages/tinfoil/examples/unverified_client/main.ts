/**
 * UnverifiedClient Example - Development/Testing Only
 *
 * WARNING: UnverifiedClient skips enclave verification. Use only for:
 * - Local development against mock endpoints
 * - Testing when verification is not required
 * - Debugging transport issues
 *
 * For production, always use TinfoilAI or SecureClient which verify the enclave.
 *
 * Run: npx ts-node main.ts
 */
import { UnverifiedClient } from "tinfoil/unsafe";

async function main() {
  try {
    const client = new UnverifiedClient();

    const response = await client.fetch("/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-oss-120b-free",
        messages: [{ role: "user", content: "Hello!" }],
      }),
    });

    const data = await response.json();
    console.log("Response:", data.choices[0]?.message?.content);
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
