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
 * - Point TINFOIL_UNVERIFIED_URL at your development server, for example
 *   export TINFOIL_UNVERIFIED_URL="http://localhost:8080/v1/"
 * - Export the credential that server expects: export TINFOIL_API_KEY="<KEY>"
 *
 * Run: npx ts-node main.ts
 */
import { UnverifiedClient } from "tinfoil/unsafe";

async function main() {
  // The client never discovers a server by itself, and this example never
  // defaults to one: a URL is required, so nothing real is sent unverified
  // by accident.
  const baseURL = process.env.TINFOIL_UNVERIFIED_URL;
  if (!baseURL) {
    console.error("TINFOIL_UNVERIFIED_URL is required: the base URL of the development server to talk to without attestation.");
    process.exit(1);
  }

  try {
    const client = await UnverifiedClient.create({ baseURL });

    // Requests take an absolute URL; client.baseURL ends with "/", so a path
    // resolves under it.
    const response = await client.fetch(new URL("chat/completions", client.baseURL), {
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
