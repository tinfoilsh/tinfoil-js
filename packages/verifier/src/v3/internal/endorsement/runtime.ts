/** Provenance of the IGVM runtime release pinned by a config. */
import type { RuntimeCollateral, RuntimeReference } from "../../document/collateral/runtime.js";
import { notImplemented } from "../../errors.js";
import type { Manifest } from "../runtime/manifest.js";
import type { ProvenanceClient } from "./provenance.js";
import type { AuthenticatedArtifact } from "./reference.js";

export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";

export interface RuntimeArtifact extends AuthenticatedArtifact {
  readonly manifest: Manifest;
}

/**
 * Verifies a runtime release: the collateral's reference equals `expected`,
 * the manifest matches the pinned digest and version, and the bundle is
 * signed by the release workflow at the tag, with a SLSA provenance
 * statement naming the manifest as its subject.
 */
export async function authenticateRuntime(client: ProvenanceClient, material: RuntimeCollateral, expected: RuntimeReference): Promise<RuntimeArtifact> {
  return notImplemented("endorsement.authenticateRuntime");
}
