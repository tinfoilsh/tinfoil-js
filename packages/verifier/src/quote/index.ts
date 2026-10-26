import type { CPUEndorsements } from '../document.js';
import type { ExpectedMeasurement, Measurement, SNPMeasurement, TDXMeasurement } from '../types.js';
import { atLayer } from '../errors.js';
import { authenticateSEV } from '../sev/authenticate.js';
import type { Report } from '../sev/report.js';
import { validateSEV } from '../sev/policy.js';
import { authenticateTDX, type AuthenticatedTDX } from '../tdx/authenticate.js';
import { validateTDX } from '../tdx/policy.js';
import { parsePlatformArtifact, PLATFORM_V1, PLATFORM_V2, shapeMatches, type PlatformArtifact, type Shape } from '../policy/index.js';
import { concat, requireThat, unhex } from './crypto.js';

export type { CPUEndorsements } from '../document.js';
export type { PCSResponse } from '../tdx/collateral.js';
export type { PlatformArtifact, Shape } from '../policy/index.js';
export interface QuoteEvidence { format: string; report: Uint8Array }
/** Internal per-call test seam. Never accepted by the public verifier options. */
export interface QuoteTrust { amdRootPem?: string; intelRootPem?: string }
export interface AuthenticatedQuote { readonly platform: 'sev-snp' | 'tdx'; readonly identity: string; readonly measurement: Measurement }
interface State { evidence: QuoteEvidence; sev?: Report; tdx?: AuthenticatedTDX }
const authenticated = new WeakMap<AuthenticatedQuote, State>();
export function authenticateQuote(evidence: QuoteEvidence, endorsements: CPUEndorsements, now: Date, privateTrust?: QuoteTrust): Promise<AuthenticatedQuote> {
  return atLayer('quote', async () => {
    requireThat(Number.isFinite(now.getTime()), 'verification time is required');
    const copied = { format: evidence.format, report: Uint8Array.from(evidence.report) };
    let q: AuthenticatedQuote, state: State;
    switch (evidence.format) {
      case 'https://tinfoil.sh/format/sev-snp-report/v1': {
        requireThat(endorsements.amdVcek && endorsements.amdCrl, 'SEV authentication requires AMD VCEK and CRL collateral');
        const sev = await authenticateSEV({ report: copied.report, ...endorsements.amdVcek, ...endorsements.amdCrl }, now, privateTrust?.amdRootPem);
        q = Object.freeze({ platform: 'sev-snp', identity: sev.identity, measurement: Object.freeze({ type: 'sev-snp', launch: sev.launch }) }); state = { evidence: copied, sev }; break;
      }
      case 'https://tinfoil.sh/format/tdx-quote/v1': {
        requireThat(endorsements.intelPcs, 'TDX authentication requires Intel PCS collateral');
        const tdx = await authenticateTDX(copied.report, endorsements.intelPcs.responses, now, privateTrust?.intelRootPem);
        const [rtmr0, rtmr1, rtmr2, rtmr3] = tdx.quote.rtmrs;
        q = Object.freeze({ platform: 'tdx', identity: tdx.identity, measurement: Object.freeze({ type: 'tdx', mrtd: tdx.quote.mrtd, rtmr0, rtmr1, rtmr2, rtmr3 }) }); state = { evidence: copied, tdx }; break;
      }
      default: throw new Error('unsupported CPU evidence format');
    }
    authenticated.set(q, state); return q;
  });
}
export interface ReferenceValues {
  kind: 'release' | 'config'; platformArtifact: PlatformArtifact | unknown;
  snp: Extract<ExpectedMeasurement, { type: 'sev-snp' }> | SNPMeasurement;
  tdx: Extract<ExpectedMeasurement, { type: 'tdx' }> | TDXMeasurement;
  shape?: Shape; configHash?: string;
}
export interface PolicyResult { codeMeasurement: ExpectedMeasurement; policyName: string; platformMeasurementName: string }
function mergePins(code: ExpectedMeasurement, pins?: ExpectedMeasurement): ExpectedMeasurement {
  if (!pins) return { ...code };
  requireThat(code.type === pins.type, 'measurement pins are for the wrong platform');
  const result: Record<string, string> = { ...code };
  const allowed = code.type === 'sev-snp' ? ['type', 'launch'] : ['type', 'mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'];
  for (const [name, value] of Object.entries(pins)) {
    requireThat(allowed.includes(name), 'unknown pinned measurement register');
    if (name === 'type' || value === undefined) continue;
    unhex(value, 48); requireThat(!result[name] || result[name] === value, `pinned ${name} conflicts with signed release`); result[name] = value;
  }
  return result as unknown as ExpectedMeasurement;
}
export function validatePolicy(q: AuthenticatedQuote, refs: ReferenceValues, reportData: Uint8Array, pins?: ExpectedMeasurement): Promise<PolicyResult> {
  return atLayer('policy', () => {
    const state = authenticated.get(q); requireThat(state, 'authenticated quote is required');
    requireThat(reportData.length === 64, 'expected REPORT_DATA must be 64 bytes');
    const artifact = parsePlatformArtifact(refs.platformArtifact, refs.kind === 'release' ? PLATFORM_V1 : PLATFORM_V2);
    const policyName = artifact.machines[q.identity]; requireThat(policyName !== undefined, 'hardware identity is not endorsed');
    const policy = artifact.policies[policyName]; requireThat(policy.platform === q.platform, 'machine policy is for the wrong platform');
    const code = q.platform === 'sev-snp' ? refs.snp : refs.tdx;
    requireThat(code && code.type === q.platform, 'release is missing required platform measurements');
    let expected = mergePins(code, pins), platformMeasurementName = '';
    if (refs.kind === 'config') requireThat(refs.configHash && /^[0-9a-f]{64}$/.test(refs.configHash), 'config binding digest is required');
    if (state.sev && policy.platform === 'sev-snp' && expected.type === 'sev-snp') {
      requireThat(expected.launch, 'nothing fixes the expected SNP launch measurement');
      validateSEV(state.sev, policy.sev_snp, expected.launch, reportData, refs.kind === 'config' ? refs.configHash! : policy.sev_snp.host_data!);
    } else if (state.tdx && policy.platform === 'tdx' && expected.type === 'tdx') {
      if (refs.kind === 'release') {
        requireThat(refs.shape, 'release must declare required VM shape');
        const candidate = (policy.tdx.platform_measurements ?? []).find(name => {
          const m = artifact.measurements[name]; return shapeMatches(m.shape, refs.shape!) && m.mrtd === state.tdx!.quote.mrtd && m.rtmr0 === state.tdx!.quote.rtmrs[0];
        });
        requireThat(candidate !== undefined, 'no endorsed platform measurement matches this quote and VM shape');
        platformMeasurementName = candidate;
        const m = artifact.measurements[candidate];
        expected = { ...expected, mrtd: expected.mrtd ?? m.mrtd, rtmr0: expected.rtmr0 ?? m.rtmr0, rtmr3: expected.rtmr3 ?? '00'.repeat(48) };
      }
      for (const field of ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'] as const) requireThat(expected[field], `nothing fixes the expected ${field}`);
      const configID = refs.kind === 'config' ? concat(unhex(refs.configHash!, 32), new Uint8Array(16)) : new Uint8Array(48);
      validateTDX(state.tdx, policy.tdx, expected as TDXMeasurement, reportData, configID);
    } else throw new Error('quote and expected platform do not match');
    return { codeMeasurement: { ...code }, policyName, platformMeasurementName };
  });
}
