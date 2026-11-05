/**
 * Which repository a model's replicas are verified against, and under which
 * policy: a pin the caller set, or the untrusted catalog's repository under
 * the default policy. Pinned-only mode serves nothing else.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import { parseReference, Verifier } from "@tinfoilsh/verifier";
import { AttestationError, ConfigurationError, messageOf } from "../../errors.js";
import type { Catalog, ModelPin } from "../../options.js";
import { TRUSTED_REPO_OWNER, trusted } from "./catalog.js";

/**
 * A replica to verify: its host, the reference it is verified against, and the model whose pin set the reference, if any.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface Replica {
  readonly host: string;
  readonly ref: string;
  readonly model: string;
}

/**
 * The key under which a replica's transport is kept.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function replicaKey(r: Replica): string {
  return `${r.host}\0${r.ref}\0${r.model}`;
}

interface ResolvedPin {
  readonly repo: string;
  readonly verifier: Verifier;
}

/** @experimental The gateway route is new; this API may change without a major version. */
export class GatewayPolicy {
  readonly #pins: ReadonlyMap<string, ResolvedPin>;
  readonly #pinnedOnly: boolean;
  readonly #verifier: Verifier;

  private constructor(pins: ReadonlyMap<string, ResolvedPin>, pinnedOnly: boolean, verifier: Verifier) {
    this.#pins = pins;
    this.#pinnedOnly = pinnedOnly;
    this.#verifier = verifier;
  }

  /** Checks the pins and the policies; every failure is a {@link ConfigurationError}. */
  static async create(modelPins: ReadonlyMap<string, ModelPin> | undefined, pinnedOnly: boolean, verifier: Verifier | undefined): Promise<GatewayPolicy> {
    const pins = modelPins ?? new Map<string, ModelPin>();
    if (pinnedOnly && pins.size === 0) throw new ConfigurationError("pinned-only mode requires at least one model pin");
    if (verifier === undefined) {
      try {
        verifier = await Verifier.create();
      } catch (err) {
        throw new ConfigurationError(`gateway verification options: ${messageOf(err)}`, { cause: err });
      }
    }
    if (verifier.callerAuthorizesConfig()) throw new ConfigurationError(CALLER_AUTHORIZED);
    const resolved = new Map<string, ResolvedPin>();
    for (const [model, pin] of pins) {
      if (pin.verifier?.callerAuthorizesConfig()) throw new ConfigurationError(`model ${JSON.stringify(model)}: ${CALLER_AUTHORIZED}`);
      if (model.trim() === "" || !pin.repo.startsWith(TRUSTED_REPO_OWNER)) {
        throw new ConfigurationError(`model pin ${JSON.stringify(model)} repository ${JSON.stringify(pin.repo)} must belong to ${TRUSTED_REPO_OWNER}`);
      }
      try {
        parseReference(pin.repo);
      } catch (err) {
        throw new ConfigurationError(`model ${JSON.stringify(model)}: ${messageOf(err)}`, { cause: err });
      }
      resolved.set(model, { repo: pin.repo, verifier: pin.verifier ?? verifier });
    }
    return new GatewayPolicy(resolved, pinnedOnly, verifier);
  }

  /**
   * The replica hosts serving `model` and what they are verified against. A
   * model the policy doesn't serve is a {@link ConfigurationError}; a catalog
   * offering a pinned model from another repository is an
   * {@link AttestationError}.
   */
  resolve(model: string, catalog: Catalog): { hosts: readonly string[]; replica: Omit<Replica, "host"> } {
    const pin = this.#pins.get(model);
    if (this.#pinnedOnly && pin === undefined) throw new ConfigurationError(`model ${JSON.stringify(model)} is not pinned`);
    const entry = catalog.get(model);
    if (!trusted(entry)) {
      throw new ConfigurationError(`model ${JSON.stringify(model)} has no valid bare ${TRUSTED_REPO_OWNER} repository with replicas in the gateway catalog`);
    }
    if (pin !== undefined) {
      const repo = pin.repo.split("@", 1)[0]!;
      if (entry.repo !== repo) {
        throw new AttestationError(`model ${JSON.stringify(model)}: expected repository ${JSON.stringify(repo)}, gateway offered ${JSON.stringify(entry.repo)}`);
      }
      return { hosts: entry.hosts, replica: { ref: pin.repo, model } };
    }
    return { hosts: entry.hosts, replica: { ref: entry.repo, model: "" } };
  }

  /** Whether the policy serves `model` from `catalog`. */
  serves(model: string, catalog: Catalog): boolean {
    try {
      this.resolve(model, catalog);
      return true;
    } catch {
      return false;
    }
  }

  /** The policy a replica of `r` is verified under. */
  verifierFor(r: Omit<Replica, "host">): Verifier {
    return this.#pins.get(r.model)?.verifier ?? this.#verifier;
  }
}

/** Gateway replicas are verified against repository pins, so a config the caller supplies or authorizes has no place. */
const CALLER_AUTHORIZED = "caller-authorized config requires a direct enclave client";
