const BASE = '/api/reserves';
async function post(path: string, body: Record<string, any> = {}): Promise<any> {
  return (await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
}
async function get(path: string): Promise<any> { return (await fetch(`${BASE}${path}`)).json(); }

export const api = {
  status: () => get('/status'),
  listAccounts: (page: number, size: number) => get(`/accounts?page=${page}&size=${size}`),
  addAccounts: (count: number) => post('/accounts/add', { count }),
  buildTree: () => post('/build-tree'),
  prove: (reservesAda: number, forceOnChain?: boolean) => post('/prove', { reservesAda, forceOnChain }),
  verifyAccount: (accountId: string) => get(`/verify/${accountId}`),
};
