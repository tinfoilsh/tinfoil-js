import { createHash, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { connect } from 'node:tls';

export async function assertTLS(endpoint: URL, expected: string): Promise<void> {
  const host = endpoint.hostname.replace(/^\[|\]$/g, '');
  await new Promise<void>((resolve, reject) => {
    const socket = connect({ host, port: Number(endpoint.port || 443), servername: isIP(host) ? undefined : host, rejectUnauthorized: true });
    socket.setTimeout(30_000, () => socket.destroy(new Error('TLS binding check timed out')));
    socket.once('error', reject);
    socket.once('secureConnect', () => {
      try {
        const peer = new X509Certificate(socket.getPeerCertificate().raw);
        const fingerprint = createHash('sha256').update(peer.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
        if (fingerprint !== expected) throw new Error('Live TLS SPKI differs from endorsed fingerprint');
        resolve();
      } catch (error) { reject(error); }
      finally { socket.end(); }
    });
  });
}
