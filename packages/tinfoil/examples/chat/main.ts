/**
 * Basic Chat Completion Example
 *
 * The simplest way to use Tinfoil - create a client and make a chat request.
 * Verification and encryption happen automatically.
 *
 * Prerequisites:
 * - Export your API key: export TINFOIL_API_KEY="<YOUR_API_KEY>"
 *
 * Run: npx ts-node main.ts
 */
import { TinfoilAI } from "tinfoil";

async function main() {
  try {
    const client = new TinfoilAI({
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