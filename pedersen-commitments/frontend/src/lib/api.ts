// Native fetch only (no axios). Every call resolves to { ok, data }; errors carry the
// server's JSON body (noProof / onChainValidation) for the error panel.
export type ApiResult = { ok: boolean; data: any };

async function call(method: string, path: string, body?: unknown): Promise<ApiResult> {
  try {
    const res = await fetch(`/api${path}`, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({ error: res.statusText }));
    return { ok: res.ok, data };
  } catch (e: any) {
    return { ok: false, data: { error: e?.message ?? String(e) } };
  }
}

export const get = (path: string) => call('GET', path);
export const post = (path: string, body: unknown = {}) => call('POST', path, body);
