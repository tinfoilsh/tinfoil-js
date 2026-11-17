/**
 * Basic Chat Completion Example
 *
 * The simplest way to use Tinfoil: create a client and make a chat request.
 * The client verifies the enclave before it is returned, and every request
 * it sends is bound to the verified enclave.
 *
 * Prerequisites:
 * - Export your API key: export TINFOIL_API_KEY="<YOUR_API_KEY>"
 *
 * Run from packages/tinfoil: npx ts-node examples/chat/main.ts
 */
import { createClient } from "tinfoil";

async function main() {
  try {
    const client = await createClient({
      apiKey: process.env.TINFOIL_API_KEY,
    });

    const completion = await client.chat.completions.create({
      messages: [{ role: "user", content: "Hello!" }],
      model: "gpt-oss-120b",
    });

    console.log(completion.choices[0]?.message?.content);
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
