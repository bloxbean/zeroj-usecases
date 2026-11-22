// The chain indexer the customer check reads: Yaci Store's REST API, called from the browser
// (Yaci Store allows cross-origin GETs on /api/**). Mirrors YaciStoreIndexer.java: pages start at
// 1 (Yaci Store reads page=0 as page 1), a 404 reads as "nothing", anything else non-2xx throws.

export function yaciStoreIndexer(baseUrl) {
  const base = baseUrl.endsWith('/') ? baseUrl : baseUrl + '/';

  async function get(path) {
    const res = await fetch(base + path, { headers: { Accept: 'application/json' } });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`${path} returned HTTP ${res.status}`);
    return res.json();
  }

  return {
    async latestBlockTimeMs() {
      const block = await get('blocks/latest');
      if (!block || !Number.isSafeInteger(block.time)) throw new Error('no latest block time');
      return BigInt(block.time) * 1000n;
    },

    async assetUtxos(unit, count) {
      const body = await get(`assets/${unit}/utxos?page=1&count=${count}`);
      if (body == null) return [];
      if (!Array.isArray(body)) throw new Error('asset utxos: not a list');
      return body.map((u) => {
        const amounts = {};
        for (const a of u.amount ?? []) amounts[a.unit] = (amounts[a.unit] ?? 0n) + BigInt(a.quantity);
        return { txHash: u.tx_hash, outputIndex: u.output_index, address: u.address, amounts, inlineDatum: u.inline_datum ?? null };
      });
    },

    async assetHistory(unit, page, count) {
      if (page < 1) throw new Error('pages start at 1');
      const body = await get(`assets/${unit}/history?page=${page}&count=${count}`);
      if (body == null) return [];
      if (!Array.isArray(body)) throw new Error('asset history: not a list');
      return body.map((e) => {
        if (e.quantity == null) throw new Error('asset history: entry without quantity');
        return { txHash: e.tx_hash, unit: e.unit ?? null, quantity: BigInt(e.quantity) };
      });
    },
  };
}
