/**
 * Client Example - Low-level Verified Fetch
 *
 * Client provides a fetch-compatible API with automatic enclave verification
 * and end-to-end encryption. Use this when you need more control than TinfoilAI,
 * or when integrating with non-OpenAI-compatible endpoints.
 *
 * Prerequisites:
 * - Export your API key: export TINFOIL_API_KEY="<YOUR_API_KEY>"
 *
 * Run: npx ts-node main.ts
 */
import { Client } from "tinfoil";

async function main() {
  try {
    const client = new Client();

    const response = await client.fetch("/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.TINFOIL_API_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-oss-120b",
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