/**
 * HTTP Client Example - Verified Fetch
 *
 * RouterHTTPClient gives a fetch-compatible `fetch` bound to the verified
 * enclave: the client verifies the router before it is returned, and every
 * request goes to that enclave over the pinned (or sealed) transport. Use it
 * when you need more control than the OpenAI client, or when calling
 * endpoints the OpenAI client does not cover. EnclaveHTTPClient.create(host,
 * { repo }) does the same for one named enclave.
 *
 * Prerequisites:
 * - Export your API key: export TINFOIL_API_KEY="<YOUR_API_KEY>"
 *
 * Run: npx ts-node main.ts
 */
import { RouterHTTPClient } from "tinfoil";

async function main() {
  try {
    const client = await RouterHTTPClient.create();
    console.log("Verified enclave:", client.enclave);

    // Request URLs are absolute. baseURL is where the client's requests go
    // and ends with "/", so a relative path resolves under it, keeping any
    // path a proxy base URL carries.
    const response = await client.fetch(new URL("v1/chat/completions", client.baseURL), {
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
