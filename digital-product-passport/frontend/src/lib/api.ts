const BASE = '/api/dpp';
async function post(path: string, body: Record<string, any> = {}): Promise<any> {
  return (await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
}
async function get(path: string): Promise<any> { return (await fetch(`${BASE}${path}`)).json(); }

export const api = {
  status: () => get('/status'),
  listProducts: (page: number, size: number, type?: string) =>
    get(`/products?page=${page}&size=${size}${type ? '&type=' + type : ''}`),
  addProducts: (count: number, type: string) => post('/products/add', { count, type }),
  verify: (id: string, type: string) => post('/verify', { id, type }),
  mint: (id: string) => post('/mint', { id }),
  anchor: () => post('/anchor'),
  registry: () => get('/registry'),
};
