/**
 * Streaming Chat Completion Example
 *
 * Stream responses token-by-token using server-sent events (SSE).
 * Useful for chat UIs where you want to display responses as they're generated.
 *
 * Prerequisites:
 * - Set TINFOIL_API_KEY environment variable, or pass apiKey to constructor
 *
 * Run: npx ts-node main.ts
 */
import { TinfoilAI } from "tinfoil";

async function main() {
  try {
    const client = new TinfoilAI();

    console.log("Streaming response:\n");

    const stream = await client.chat.completions.create({
      messages: [
        { role: "user", content: "Write a short poem about secure computing." },
      ],
      model: "gpt-oss-120b-free",
      stream: true,
    });

    // Process chunks as they arrive
    for await (const chunk of stream) {
      const content = chunk.choices[0]?.delta?.content;
      if (content) {
        process.stdout.write(content);
      }
    }

    console.log("\n\nStream complete.");
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
