import { str } from "../../internal/json/decode.js";
import { decodeBase64 } from "../../internal/canonical.js";
import { unmarshalData, type Entry } from "./collateral.js";

/** Decoded amd-vcek collateral; the chain is ASK then ARK. */
export interface AmdVcek {
  readonly vcekDer: Uint8Array;
  readonly certChainPem: string;
}

/** Decoded amd-crl collateral. */
export interface AmdCrl {
  readonly crlDer: Uint8Array;
}

export function decodeAmdVcek(entry: Entry): AmdVcek {
  const data = unmarshalData(entry, "amd-vcek", ["vcek_der_base64", "cert_chain_pem"], (o) => ({
    vcekDerBase64: str(o, "vcek_der_base64"),
    certChainPem: str(o, "cert_chain_pem"),
  }));
  return {
    vcekDer: withEntry("amd-vcek", entry, () => decodeBase64("vcek_der_base64", data.vcekDerBase64)),
    certChainPem: data.certChainPem,
  };
}

export function decodeAmdCrl(entry: Entry): AmdCrl {
  const crl = unmarshalData(entry, "amd-crl", ["crl_der_base64"], (o) => str(o, "crl_der_base64"));
  return { crlDer: withEntry("amd-crl", entry, () => decodeBase64("crl_der_base64", crl)) };
}

function withEntry<T>(label: string, entry: Entry, f: () => T): T {
  try {
    return f();
  } catch (err) {
    throw new Error(`${label} collateral entry "${entry.id}": ${(err as Error).message}`);
  }
}
