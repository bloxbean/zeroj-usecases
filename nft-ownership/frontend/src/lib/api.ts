/**
 * Backend API client — uses native fetch (NO axios).
 */

const BASE_URL = '/api';

async function post(path: string, body: Record<string, unknown> = {}): Promise<any> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function get(path: string): Promise<any> {
  const res = await fetch(`${BASE_URL}${path}`);
  return res.json();
}

export const api = {
  // NFTs (minted into the server's custody wallet)
  mint: (collectionName: string, count: number) =>
    post('/mint', { collectionName, count }),
  mintStatus: () => get('/mint/status'),

  // Snapshot. Without a secret the server draws a fresh 252-bit holder secret.
  registerHolder: (tokenName: string, secretKey?: string) =>
    post('/snapshot/register', { tokenName, ...(secretKey ? { secretKey } : {}) }),
  buildSnapshot: () => post('/snapshot/build'),
  snapshotStatus: () => get('/snapshot/status'),

  // Proof (for this run's event)
  generateProof: (secretKey: string, tokenName: string) =>
    post('/prove', { secretKey, tokenName }),

  // Access
  requestAccess: (nullifier: string) =>
    post('/access', { nullifier }),

  // Status
  status: () => get('/status'),
};
