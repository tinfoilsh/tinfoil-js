import { writeFile } from 'node:fs/promises';
import { randomNonce, fetchAttestationDocument, verifyDocumentV3At, parseReference, UsageError } from '@tinfoilsh/verifier';
import { parseJSON } from '../../verifier/src/encoding.js';
import { capabilities, errorVerdict, runAdapter, verificationFacts } from './adapter.js';
import { assertTLS } from './live.js';
import { reject } from './wire.js';

const stage = process.argv[2] ?? '';
if (stage === 'capabilities') {
  process.stdout.write(JSON.stringify(capabilities()) + '\n');
} else {
  let value: unknown;
  try {
    const chunks: Uint8Array[] = [];
    for await (const chunk of process.stdin) chunks.push(new Uint8Array(chunk));
    value = parseJSON(new Uint8Array(Buffer.concat(chunks)));
  }
  catch {
    const result = reject(stage, 'MALFORMED_INPUT');
    process.stdout.write(JSON.stringify(result.output) + '\n');
    process.exitCode = result.exit;
  }
  if (value !== undefined) {
    if (stage === 'live-verify' || stage === 'capture') {
      try {
        const input = value as { host: string; repo: string; output?: string };
        if (!input || typeof input.host !== 'string' || typeof input.repo !== 'string') throw new UsageError('Live input requires host and repo');
        let endpoint: URL;
        try { endpoint = new URL(input.host.includes('://') ? input.host : `https://${input.host}`); }
        catch (cause) { throw new UsageError('Invalid live endpoint', { cause }); }
        if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password) throw new UsageError('Live endpoint must use HTTPS');
        parseReference(input.repo);
        const nonce = randomNonce();
        const bytes = await fetchAttestationDocument(endpoint.href, nonce, { signal: AbortSignal.timeout(30_000) });
        const at = new Date();
        const verified = await verifyDocumentV3At(bytes, nonce, input.repo, at);
        const facts = verificationFacts(verified);
        await assertTLS(endpoint, facts.tls_public_key_fp!);
        if (stage === 'capture') {
          const fixture = { id: `capture-${endpoint.hostname}`, stage: 'verify-attestation-v3', input: {
            schema_version: '1', document_b64: Buffer.from(bytes).toString('base64'), nonce_hex: Buffer.from(nonce).toString('hex'),
            repo: input.repo, verification_time_unix: Math.floor(at.getTime() / 1000),
          }, expected: { accepted: true, ...facts } };
          const encoded = JSON.stringify(fixture, null, 2) + '\n';
          if (input.output) await writeFile(input.output, encoded, { flag: 'wx' });
          process.stdout.write(encoded);
        } else process.stdout.write(JSON.stringify({ stage, accepted: true, outputs: { ...facts, channel_binding: 'tls-spki' } }) + '\n');
      } catch (error) {
        const result = errorVerdict(stage, error);
        process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
        process.stdout.write(JSON.stringify(result.output) + '\n');
        process.exitCode = result.exit;
      }
    } else {
      const result = await runAdapter(stage, value);
      if (process.env.TINFOIL_CONFORMANCE_DEBUG && result.diagnostic) process.stderr.write(result.diagnostic + '\n');
      process.stdout.write(JSON.stringify(result.output) + '\n');
      process.exitCode = result.exit;
    }
  }
}
