export interface SNPMeasurement {
  readonly type: "sev-snp";
  readonly launch: string;
}
export interface TDXMeasurement {
  readonly type: "tdx";
  readonly mrtd: string;
  readonly rtmr0: string;
  readonly rtmr1: string;
  readonly rtmr2: string;
  readonly rtmr3: string;
}
export type Measurement = SNPMeasurement | TDXMeasurement;
export type ExpectedMeasurement =
  | { readonly type: "sev-snp"; readonly launch?: string }
  | {
      readonly type: "tdx";
      readonly mrtd?: string;
      readonly rtmr0?: string;
      readonly rtmr1?: string;
      readonly rtmr2?: string;
      readonly rtmr3?: string;
    };
export interface CryptoMaterialItem {
  readonly id: string;
  readonly format: string;
  readonly data: string;
}
export type ReferenceSource = "endorsement" | "embedded" | "policy";
export interface ConfigVerification {
  readonly source: ReferenceSource;
  readonly name: string;
  readonly digest: string;
  readonly reference: string;
  readonly signingKeyHint: string;
  readonly approvalTime?: Date;
}
export interface ArtifactVerification {
  readonly source: ReferenceSource;
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
  readonly name: string;
  readonly commit: string;
  readonly approvalTime?: Date;
}
export interface VerificationMetadata {
  readonly verifier: { readonly name: string; readonly version: string };
  readonly verifiedAt: Date;
}
export interface EmbeddedReferences {
  readonly config?: { readonly bytes: Uint8Array; readonly name?: string };
  readonly runtime?: Uint8Array;
  readonly platform?: Uint8Array;
}
export interface UntrustedConfig {
  readonly config: Uint8Array;
  readonly reference: string;
  readonly bundle: unknown;
}
export interface VerifierOptions {
  readonly freshnessMaxAgeMs?: number;
  readonly pinnedRegisters?: ExpectedMeasurement;
  readonly configSigningKeys?: readonly Uint8Array[];
  readonly freshnessSigningKeys?: readonly Uint8Array[];
  readonly embeddedReferences?: EmbeddedReferences;
  readonly configAuthorizer?: (
    material: UntrustedConfig,
  ) => void | Promise<void>;
}
