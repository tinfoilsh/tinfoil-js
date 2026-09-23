// v3 rejection model: every verification failure throws a VerificationError
// tagged with the layer that rejected. The conformance adapter maps the layer
// to the wire rejection code; MALFORMED_INPUT is adapter-level and never a
// VerificationError layer.

export type RejectionLayer =
  | "ENVELOPE_REJECTED"
  | "PROVENANCE_REJECTED"
  | "QUOTE_REJECTED"
  | "POLICY_REJECTED";

export class VerificationError extends Error {
  readonly layer: RejectionLayer;

  constructor(layer: RejectionLayer, message: string) {
    super(message);
    this.name = "VerificationError";
    this.layer = layer;
  }
}

// CollateralNotFoundError reports that a document carries no collateral entry
// of the requested role and format (Go: envelope.ErrCollateralNotFound).
export class CollateralNotFoundError extends VerificationError {
  constructor(layer: RejectionLayer, message: string) {
    super(layer, message);
    this.name = "CollateralNotFoundError";
  }
}
