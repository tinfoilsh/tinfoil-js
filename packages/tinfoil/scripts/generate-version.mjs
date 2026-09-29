import { readFileSync, writeFileSync } from 'node:fs';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

writeFileSync(
  new URL('../src/version.ts', import.meta.url),
  '// Generated from package.json by scripts/generate-version.mjs.\n' +
  "export const SDK_NAME = 'tinfoil-js';\n" +
  `export const SDK_VERSION = ${JSON.stringify(version)};\n`,
);
