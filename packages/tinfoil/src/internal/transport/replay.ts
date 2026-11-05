/**
 * One application replay: a request sent again when the first attempt fails
 * with an error the caller deems retryable and the body can be sent again.
 * The routes pass the key-rejection check: the rejection has already
 * invalidated the verification, so the replay goes out under a fresh one.
 */
import { AttestationError, ConfigurationError, messageOf, NetworkError, TinfoilError } from "../../errors.js";
import type { Fetch } from "../../options.js";

/** `next` with one replay of a request that fails `retryable`. */
export function withReplay(next: Fetch, retryable: (err: unknown) => boolean): Fetch {
  return async (input, init) => {
    const attempts = prepare(input, init);
    try {
      return await next(attempts.first, init);
    } catch (err) {
      if (!retryable(err)) throw err;
      if (attempts.again === undefined) throw withNote(err, "cannot replay the request after key rotation: body is not replayable");
      if (init?.signal?.aborted) throw withNote(err, "request aborted before it could be replayed");
      try {
        return await next(attempts.again, init);
      } catch (retryErr) {
        throw withNote(retryErr, `the replay failed too; first attempt: ${messageOf(err)}`);
      }
    }
  };
}

/**
 * The input for the first attempt and, when the body can be sent again, for
 * the replay. A body given as a stream is consumed by the first attempt; a
 * Request's body is split so each attempt reads its own copy.
 */
function prepare(input: string | URL | Request, init: RequestInit | undefined): { first: string | URL | Request; again: string | URL | Request | undefined } {
  if (init?.body instanceof ReadableStream) return { first: input, again: undefined };
  if (input instanceof Request && input.body !== null) return { first: input.clone(), again: input };
  return { first: input, again: input };
}

/**
 * The terminal failure: `err` with `note` appended, keeping its category and
 * cause. It is a plain error of that category, not the subclass `err` was:
 * a key rejection no longer invites a replay once this layer has given up.
 */
function withNote(err: unknown, note: string): TinfoilError {
  if (!(err instanceof TinfoilError)) return new AttestationError(`${messageOf(err)}; ${note}`, { cause: err });
  const message = `${stripCategory(err)}; ${note}`;
  const options = { cause: err.cause ?? err };
  if (err instanceof NetworkError) return new NetworkError(message, options);
  if (err instanceof ConfigurationError) return new ConfigurationError(message, options);
  return new AttestationError(message, options);
}

function stripCategory(err: TinfoilError): string {
  const prefix = `${err.category} error: `;
  return err.message.startsWith(prefix) ? err.message.slice(prefix.length) : err.message;
}
