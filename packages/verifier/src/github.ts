import { FetchError, wrapOrThrow } from './errors.js';

export interface Release {
  tag_name: string;
  body: string;
}

interface GitHubAttestationResponse {
  attestations: Array<{
    bundle: unknown;
  }>;
}

/**
 * Gets the latest release and attestation digest of a repo.
 *
 * @param repo - The GitHub repository in format "owner/repo"
 * @returns The digest string
 * @throws Error if there's any error fetching or parsing the data
 */
export async function fetchLatestDigest(repo: string): Promise<string> {
  const url = `https://api-github-proxy.tinfoil.sh/repos/${repo}/releases/latest`;
  const releaseResponse = await fetch(url);

  if (!releaseResponse.ok) {
    throw new FetchError(`Failed to fetch latest release from GitHub for ${repo}: HTTP ${releaseResponse.status} ${releaseResponse.statusText}`);
  }

  const responseData: Release = await releaseResponse.json();
  const tagName = responseData.tag_name;
  const body = responseData.body;

  // Backwards compatibility for old EIF releases
  const eifRegex = /EIF hash: ([a-fA-F0-9]{64})/;
  const eifMatches = eifRegex.exec(body);
  if (eifMatches) {
    return eifMatches[1];
  }

  // Other format to fetch Digest
  const digestRegex = /Digest: `([a-fA-F0-9]{64})`/;
  const digestMatches = digestRegex.exec(body);
  if (digestMatches) {
    return digestMatches[1];
  }

  // Fallback option: fetch digest from github special endpoint
  const digestUrl = `https://github-proxy.tinfoil.sh/${repo}/releases/download/${tagName}/tinfoil.hash`;
  const response = await fetch(digestUrl);

  if (!response.ok) {
    throw new FetchError(`Failed to fetch release digest for ${repo} tag ${tagName}: HTTP ${response.status} ${response.statusText}`);
  }

  return (await response.text()).trim();
}

/**
 * Fetches the sigstore bundle from a repo for a given repo and EIF hash.
 *
 * @param repo - The GitHub repository in format "owner/repo"
 * @param digest - The EIF hash/digest
 * @returns The sigstore bundle JSON object
 * @throws Error if there's any error fetching or parsing the data
 */
export async function fetchGithubAttestationBundle(repo: string, digest: string): Promise<unknown> {
  const url = `https://api-github-proxy.tinfoil.sh/repos/${repo}/attestations/sha256:${digest}`;

  let responseData: GitHubAttestationResponse;
  try {
    const bundleResponse = await fetch(url);
    if (!bundleResponse.ok) {
      throw new FetchError(`Failed to fetch GitHub attestation bundle: HTTP ${bundleResponse.status} ${bundleResponse.statusText}`);
    }
    responseData = await bundleResponse.json();
  } catch (e) {
    wrapOrThrow(e, FetchError, `Failed to fetch Sigstore bundle from GitHub for ${repo}`);
  }

  if (!responseData.attestations?.[0]?.bundle) {
    throw new FetchError(`No attestation bundle found for ${repo} with digest ${digest}`);
  }
  return responseData.attestations[0].bundle;
}
