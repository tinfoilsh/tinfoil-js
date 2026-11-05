import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { corrections, prepareCorpus, applyCorrection } from './corpus.mjs';

const workspace = fileURLToPath(new URL('../../..', import.meta.url));
const { values } = parseArgs({ options: {
  corpus: { type: 'string' },
  report: { type: 'string' },
  runtime: { type: 'string' },
} });
const corpus = resolve(values.corpus ?? process.env.TINFOIL_CONFORMANCE_ROOT ?? resolve(workspace, '.conformance-corpus'));
const report = resolve(values.report ?? resolve(workspace, 'artifacts/conformance-report.json'));
const runtime = values.runtime ?? process.execPath;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: workspace, encoding: 'utf8', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited ${result.status}: ${result.stderr ?? ''}`);
  return result.stdout;
}

const { revision, paths } = prepareCorpus(corpus);
run('python3', [resolve(corpus, 'tools/validate_suite.py')], { stdio: 'inherit' });

// Preserve upstream bytes; materialize reason-audited contract corrections in
// the report directory. The adapter itself contains no fixture special cases.
const adopted = resolve(dirname(report), 'adopted-corpus');
rmSync(adopted, { recursive: true, force: true });
mkdirSync(adopted, { recursive: true });
for (const directory of ['vectors', 'tools']) cpSync(resolve(corpus, directory), resolve(adopted, directory), { recursive: true });
for (const correction of corrections.corrections) {
  const path = resolve(adopted, 'vectors/v3', correction.path);
  const fixture = JSON.parse(readFileSync(path, 'utf8'));
  applyCorrection(fixture, correction.path);
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n');
  process.stdout.write(`Audited contract correction ${correction.path}: ${correction.originalCode} -> ${correction.correctedCode}\n`);
}

const adapter = resolve(workspace, 'packages/conformance/dist/cli.js');
const capabilities = JSON.parse(run(runtime, [adapter, 'capabilities']));
if (capabilities.schema_version !== '1' || capabilities.v3?.supported !== true ||
    capabilities.v3.freshness_enforced !== true ||
    ['amd', 'intel', 'sigstore'].some(x => capabilities.v3.synthetic_roots?.[x] !== true)) {
  throw new Error('Adapter lacks a trust-root capability or freshness enforcement');
}
mkdirSync(dirname(report), { recursive: true });
const result = spawnSync('python3', [resolve(adopted, 'tools/run_adapter.py'), '--adapter', `${runtime} ${adapter}`, '--report', report], {
  cwd: workspace,
  stdio: 'inherit',
});
if (result.error) throw result.error;
const results = JSON.parse(readFileSync(report, 'utf8')).results;
if (result.status !== 0 || paths.some(key => results[key]?.status !== 'PASS')) {
  throw new Error('Conformance requires every upstream fixture to pass with zero skips and zero failures');
}
const complete = JSON.parse(readFileSync(report, 'utf8'));
complete.corpus = { revision, corrections: corrections.corrections };
writeFileSync(report, JSON.stringify(complete, null, 2) + '\n');
process.stdout.write(`Conformance gate passed: ${paths.length} fixtures, ${corrections.corrections.length} explicit contract correction(s), zero skips. Report: ${report}\n`);
