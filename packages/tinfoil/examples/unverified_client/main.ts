/**
 * UnverifiedClient Example - Development/Testing Only
 *
 * WARNING: UnverifiedClient skips enclave verification. Request bodies are
 * sealed to whatever key the server hands out, so it exists only to exercise
 * the EHBP protocol against a local development server. Use only for:
 * - Local development against mock endpoints
 * - Debugging transport issues
 *
 * For anything that handles real data, use the attested clients from the
 * package's main entry.
 *
 * Prerequisites:
 * - Export your API key: export TINFOIL_API_KEY="<YOUR_API_KEY>"
 * - Optionally point TINFOIL_UNVERIFIED_URL at your development server
 *
 * Run: npx ts-node main.ts
 */
import { UnverifiedClient } from "tinfoil/unsafe";

async function main() {
  try {
    // The client never discovers a server by itself: name the one to talk to.
    const baseURL = process.env.TINFOIL_UNVERIFIED_URL ?? "https://inference.tinfoil.sh/v1/";
    const client = await UnverifiedClient.create({ baseURL });

    // Relative request URLs resolve against the base URL.
    const response = await client.fetch("chat/completions", {
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
