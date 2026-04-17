const BASE_URL = '/api/credential';

async function post(path: string, body: Record<string, any> = {}): Promise<any> {
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
  status: () => get('/status'),
  verify: (name: string) => post('/verify', { name }),
  lock: (adaAmount: number) => post('/lock', { adaAmount }),
  unlock: (name: string) => post('/unlock', { name }),
};
