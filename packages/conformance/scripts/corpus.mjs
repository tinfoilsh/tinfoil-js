import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspace = fileURLToPath(new URL('../../..', import.meta.url));
const REPOSITORY = 'https://github.com/tinfoilsh/tinfoil-conformance.git';
export const corrections = JSON.parse(readFileSync(new URL('../corpus-corrections.json', import.meta.url), 'utf8'));
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: workspace, encoding: 'utf8', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited ${result.status}: ${result.stderr ?? ''}`);
  return result.stdout;
}

export function prepareCorpus(corpus = process.env.TINFOIL_CONFORMANCE_ROOT ?? resolve(workspace, '.conformance-corpus')) {
  corpus = resolve(corpus);
  if (!existsSync(corpus)) {
    mkdirSync(dirname(corpus), { recursive: true });
    run('git', ['clone', '--no-checkout', '--filter=blob:none', REPOSITORY, corpus], { stdio: 'inherit' });
    run('git', ['-C', corpus, 'checkout', '--detach', corrections.upstreamRevision], { stdio: 'inherit' });
  }
  const revision = run('git', ['-C', corpus, 'rev-parse', 'HEAD']).trim();
  if (revision !== corrections.upstreamRevision) throw new Error(`Corpus revision ${revision} differs from pinned ${corrections.upstreamRevision}`);

  if (run('git', ['-C', corpus, 'status', '--porcelain', '--untracked-files=all']).trim()) throw new Error('Corpus checkout must be clean');

  const vectorRoot = resolve(corpus, 'vectors/v3');
  const paths = readdirSync(vectorRoot, { withFileTypes: true }).filter(x => x.isDirectory()).flatMap(dir =>
    readdirSync(resolve(vectorRoot, dir.name)).filter(x => x.endsWith('.json')).map(x => `${dir.name}/${x}`),
  ).sort();
  if (!paths.length) throw new Error('Corpus contains no v3 fixtures');
  return { corpus, revision, paths, vectorRoot };
}

export function applyCorrection(fixture, path) {
  const correction = corrections.corrections.find(value => value.path === path);
  if (correction) {
    if (fixture.expected.accepted !== false || fixture.expected.code !== correction.originalCode) throw new Error(`Stale contract correction: ${path}`);
    fixture.expected.code = correction.correctedCode;
  }
  return fixture;
}
