/**
 * Backend API client — uses native fetch (NO axios).
 */

const BASE_URL = '/api';

async function post(path: string, body: Record<string, string> = {}): Promise<any> {
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
  // Snapshot
  registerHolder: (secretKey: string, tokenName: string) =>
    post('/snapshot/register', { secretKey, tokenName }),
  buildSnapshot: () => post('/snapshot/build'),
  snapshotStatus: () => get('/snapshot/status'),

  // Proof
  generateProof: (secretKey: string, tokenName: string, contextId?: string) =>
    post('/prove', { secretKey, tokenName, ...(contextId ? { contextId } : {}) }),

  // Verify & Access
  verifyProof: (nullifier: string, snapshotRoot: string) =>
    post('/verify', { nullifier, snapshotRoot }),
  requestAccess: (nullifier: string) =>
    post('/access', { nullifier }),

  // Status
  status: () => get('/status'),
};
