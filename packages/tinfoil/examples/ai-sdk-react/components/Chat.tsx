/**
 * Secure Chat Component
 * 
 * A React component demonstrating the Vercel AI SDK's useChat hook
 * with Tinfoil's secure transport for end-to-end encrypted chat.
 * 
 * This example shows:
 * - Async transport initialization with loading state
 * - Using useChat with a custom transport
 * - Proper error handling
 * - Streaming message display
 */

"use client"; // Required for Next.js App Router

import { useChat } from "@ai-sdk/react";
import { useEffect, useState } from "react";
import type { DefaultChatTransport, UIMessage } from "ai";
import { getTinfoilTransport } from "../lib/tinfoil";

export function Chat() {
  // Transport state - null until initialization completes
  const [transport, setTransport] = useState<DefaultChatTransport<UIMessage> | null>(null);
  const [initError, setInitError] = useState<Error | null>(null);

  // Initialize transport on mount
  useEffect(() => {
    getTinfoilTransport()
      .then(setTransport)
      .catch((error) => {
        console.error("Failed to initialize secure transport:", error);
        setInitError(error);
      });
  }, []);

  // useChat hook with custom transport
  // Note: transport can be undefined during initialization
  const { messages, input, handleInputChange, handleSubmit, status, error } = useChat({
    // Pass transport only when ready (undefined = hook waits)
    transport: transport ?? undefined,
    
    // Model to use - must match your Tinfoil model catalog
    // See: https://docs.tinfoil.sh/models/catalog
    body: {
      model: "gpt-oss-120b-free",
    },
    
    // Optional: Handle errors
    onError: (error) => {
      console.error("Chat error:", error);
    },
  });

  // Loading state while transport initializes
  if (!transport && !initError) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4" />
          <p className="text-gray-600">Establishing secure connection...</p>
          <p className="text-sm text-gray-400 mt-2">
            Verifying enclave attestation
          </p>
        </div>
      </div>
    );
  }

  // Error state if initialization failed
  if (initError) {
    return (
      <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
        <h3 className="font-semibold text-red-800">Connection Failed</h3>
        <p className="text-red-600 mt-1">{initError.message}</p>
        <button
          onClick={() => window.location.reload()}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full max-w-2xl mx-auto">
      {/* Secure connection indicator */}
      <div className="flex items-center gap-2 p-2 bg-green-50 border-b border-green-200">
        <span className="w-2 h-2 bg-green-500 rounded-full" />
        <span className="text-sm text-green-700">
          End-to-end encrypted connection established
        </span>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <p className="text-gray-500 text-center">
            Send a message to start the conversation
          </p>
        )}
        
        {messages.map((message) => (
          <div
            key={message.id}
            className={`p-3 rounded-lg ${
              message.role === "user"
                ? "bg-blue-100 ml-auto max-w-[80%]"
                : "bg-gray-100 mr-auto max-w-[80%]"
            }`}
          >
            <div className="text-xs text-gray-500 mb-1">
              {message.role === "user" ? "You" : "Assistant"}
            </div>
            <div className="whitespace-pre-wrap">
              {message.parts.map((part, i) => 
                part.type === "text" ? <span key={i}>{part.text}</span> : null
              )}
            </div>
          </div>
        ))}

        {/* Streaming indicator */}
        {status === "streaming" && (
          <div className="text-gray-400 text-sm">Assistant is typing...</div>
        )}
      </div>

      {/* Error display */}
      {error && (
        <div className="p-3 bg-red-50 border-t border-red-200 text-red-600">
          Error: {error.message}
        </div>
      )}

      {/* Input form */}
      <form onSubmit={handleSubmit} className="p-4 border-t">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={handleInputChange}
            placeholder="Type a message..."
            className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={status === "streaming"}
          />
          <button
            type="submit"
            disabled={status === "streaming" || !input.trim()}
            className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Send
          </button>
        </div>
      </form>
    </div>
  );
}

/**
 * Alternative: Chat with Context Provider
 * 
 * For larger apps, you might want to provide the transport via React Context
 * to avoid prop drilling and ensure consistent initialization across components.
 */

import { createContext, useContext, type ReactNode } from "react";

const TinfoilContext = createContext<DefaultChatTransport<UIMessage> | null>(null);

export function TinfoilProvider({ children }: { children: ReactNode }) {
  const [transport, setTransport] = useState<DefaultChatTransport<UIMessage> | null>(null);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    getTinfoilTransport()
      .then(setTransport)
      .catch(setError);
  }, []);

  if (error) {
    return (
      <div className="p-4 text-red-600">
        Failed to establish secure connection: {error.message}
      </div>
    );
  }

  if (!transport) {
    return (
      <div className="p-4 text-gray-600">
        Establishing secure connection...
      </div>
    );
  }

  return (
    <TinfoilContext.Provider value={transport}>
      {children}
    </TinfoilContext.Provider>
  );
}

export function useTinfoilTransport(): DefaultChatTransport<UIMessage> {
  const transport = useContext(TinfoilContext);
  if (!transport) {
    throw new Error("useTinfoilTransport must be used within TinfoilProvider");
  }
  return transport;
}

/**
 * Example usage with context:
 * 
 * ```tsx
 * // app/layout.tsx
 * export default function Layout({ children }) {
 *   return (
 *     <TinfoilProvider>
 *       {children}
 *     </TinfoilProvider>
 *   );
 * }
 * 
 * // app/chat/page.tsx
 * function ChatPage() {
 *   const transport = useTinfoilTransport();
 *   const { messages, ... } = useChat({ transport });
 *   // ...
 * }
 * ```
 */
