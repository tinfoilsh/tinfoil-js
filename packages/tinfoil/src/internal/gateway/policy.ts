/**
 * Which repository a model's replicas are verified against, and under which
 * policy: the pin that the caller set for the model. Only pinned models are
 * served; the untrusted catalog supplies their replica hosts.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import { parseReference, Verifier, type Policy } from "@tinfoilsh/verifier";
import { AttestationError, ConfigurationError, messageOf } from "../../errors.js";
import type { Catalog, ModelPin } from "../../options.js";
import { TRUSTED_REPO_OWNER, trusted } from "./catalog.js";

/**
 * A replica to verify: its host, the reference it is verified against, and the model whose pin set the reference.
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

  private constructor(pins: ReadonlyMap<string, ResolvedPin>) {
    this.#pins = pins;
  }

  /**
   * Checks the pins and builds a verifier for each policy, the gateway's
   * and each pin's own, so that later changes by the caller have no effect;
   * every failure is a {@link ConfigurationError}, including no pins at
   * all. The gateway's policy applies to the pins that set none, and it is
   * checked even when every pin sets its own. `build` builds a verifier
   * from a policy; tests replace it.
   */
  static async create(
    modelPins: ReadonlyMap<string, ModelPin> | undefined,
    policy: Policy | undefined,
    build: (policy: Policy | undefined) => Promise<Verifier> = defaultVerifier,
  ): Promise<GatewayPolicy> {
    if (modelPins === undefined || modelPins.size === 0) throw new ConfigurationError("a gateway client requires at least one model pin");
    const verifier = await built(build, policy, "gateway policy");
    const resolved = new Map<string, ResolvedPin>();
    for (const [model, pin] of modelPins) {
      if (model.trim() === "" || !pin.repo.startsWith(TRUSTED_REPO_OWNER)) {
        throw new ConfigurationError(`model pin ${JSON.stringify(model)} repository ${JSON.stringify(pin.repo)} must belong to ${TRUSTED_REPO_OWNER}`);
      }
      try {
        parseReference(pin.repo);
      } catch (err) {
        throw new ConfigurationError(`model ${JSON.stringify(model)}: ${messageOf(err)}`, { cause: err });
      }
      const pinVerifier = pin.policy === undefined ? verifier : await built(build, pin.policy, `model ${JSON.stringify(model)} policy`);
      resolved.set(model, { repo: pin.repo, verifier: pinVerifier });
    }
    return new GatewayPolicy(resolved);
  }

  /**
   * The replica hosts serving `model` and what they are verified against. A
   * model that has no pin, or that the catalog has no usable entry for, is
   * a {@link ConfigurationError}; a catalog that offers a pinned model from
   * another repository is an {@link AttestationError}.
   */
  resolve(model: string, catalog: Catalog): { hosts: readonly string[]; replica: Omit<Replica, "host"> } {
    const pin = this.#pins.get(model);
    if (pin === undefined) throw new ConfigurationError(`model ${JSON.stringify(model)} is not pinned`);
    const entry = catalog.get(model);
    if (!trusted(entry)) {
      throw new ConfigurationError(`model ${JSON.stringify(model)} has no valid bare ${TRUSTED_REPO_OWNER} repository with replicas in the gateway catalog`);
    }
    const repo = pin.repo.split("@", 1)[0]!;
    if (entry.repo !== repo) {
      throw new AttestationError(`model ${JSON.stringify(model)}: expected repository ${JSON.stringify(repo)}, gateway offered ${JSON.stringify(entry.repo)}`);
    }
    return { hosts: entry.hosts, replica: { ref: pin.repo, model } };
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

  /** The policy that a replica of `r` is verified under: the policy of `r`'s pin. */
  verifierFor(r: Omit<Replica, "host">): Verifier {
    const pin = this.#pins.get(r.model);
    // resolve() gives every replica a pinned model, so this never happens.
    if (pin === undefined) throw new ConfigurationError(`model ${JSON.stringify(r.model)} is not pinned`);
    return pin.verifier;
  }
}

/** A verifier for `policy` under the public registry, whose config trust a gateway can't change. */
function defaultVerifier(policy: Policy | undefined): Promise<Verifier> {
  return Verifier.create(undefined, policy);
}

/** `build(policy)`, with a failure as a {@link ConfigurationError} that names `what`. */
async function built(build: (policy: Policy | undefined) => Promise<Verifier>, policy: Policy | undefined, what: string): Promise<Verifier> {
  try {
    return await build(policy);
  } catch (err) {
    if (err instanceof ConfigurationError) throw err;
    throw new ConfigurationError(`${what}: ${messageOf(err)}`, { cause: err });
  }
}
