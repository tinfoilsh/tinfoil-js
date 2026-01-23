import { createTinfoilAI } from "tinfoil";
import { generateText, streamText } from "ai";

/**
 * Vercel AI SDK Integration Example
 * 
 * Demonstrates how to use Tinfoil with the Vercel AI SDK for building AI applications.
 * This is useful for Next.js apps, React Server Components, and other Vercel AI SDK features.
 * 
 * Prerequisites:
 * - Install the AI SDK: npm install ai
 * - Set TINFOIL_API_KEY environment variable
 * 
 * Related docs:
 * - Tool Calling: https://docs.tinfoil.sh/guides/tool-calling
 * - Structured Outputs: https://docs.tinfoil.sh/guides/structured-outputs
 */
async function main() {
  const apiKey = process.env.TINFOIL_API_KEY;
  if (!apiKey) {
    console.error("Please set TINFOIL_API_KEY environment variable");
    process.exit(1);
  }

  try {
    // Create a Tinfoil provider for the AI SDK
    // This performs enclave verification automatically
    const tinfoil = await createTinfoilAI(apiKey);

    // Example 1: Simple text generation
    console.log("=== Text Generation ===\n");
    
    const { text } = await generateText({
      model: tinfoil("gpt-oss-120b-free"),
      prompt: "What is confidential computing in one sentence?",
    });
    
    console.log("Response:", text);

    // Example 2: Streaming text generation
    console.log("\n=== Streaming Generation ===\n");
    
    const stream = streamText({
      model: tinfoil("gpt-oss-120b-free"),
      prompt: "Write a haiku about data privacy.",
    });

    process.stdout.write("Response: ");
    for await (const chunk of stream.textStream) {
      process.stdout.write(chunk);
    }
    console.log("\n");

    // Example 3: Chat with system message
    console.log("=== Chat with System Message ===\n");
    
    const { text: chatResponse } = await generateText({
      model: tinfoil("gpt-oss-120b-free"),
      system: "You are a helpful assistant that explains technical concepts simply.",
      prompt: "What is end-to-end encryption?",
    });
    
    console.log("Response:", chatResponse);

  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
