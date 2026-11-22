// A minimal, strict CBOR decoder for Plutus data: integers (with bignum tags 2/3), byte strings,
// lists, maps and constructors (tags 121-127, 1280-1400, 102). Anything else, or trailing bytes,
// throws.

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function decodePlutusData(hex) {
  const bytes = hexToBytes(hex);
  const [value, pos] = item(bytes, 0);
  if (pos !== bytes.length) throw new Error('trailing bytes');
  return value;
}

function arg(bytes, pos, info) {
  if (info < 24) return [BigInt(info), pos];
  const len = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
  if (!len) throw new Error('unsupported argument');
  if (pos + len > bytes.length) throw new Error('truncated');
  let v = 0n;
  for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(bytes[pos + i]);
  return [v, pos + len];
}

function byteString(bytes, pos, info) {
  if (info === 31) {
    const parts = [];
    for (;;) {
      if (pos >= bytes.length) throw new Error('truncated');
      if (bytes[pos] === 0xff) return [concat(parts), pos + 1];
      const ib = bytes[pos];
      if (ib >> 5 !== 2 || (ib & 31) === 31) throw new Error('bad chunk');
      const [chunk, next] = byteString(bytes, pos + 1, ib & 31);
      parts.push(chunk);
      pos = next;
    }
  }
  const [n, p] = arg(bytes, pos, info);
  const end = p + Number(n);
  if (end > bytes.length) throw new Error('truncated');
  return [bytes.slice(p, end), end];
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((a, b) => a + b.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function list(bytes, pos, info) {
  const items = [];
  if (info === 31) {
    for (;;) {
      if (pos >= bytes.length) throw new Error('truncated');
      if (bytes[pos] === 0xff) return [items, pos + 1];
      const [v, next] = item(bytes, pos);
      items.push(v);
      pos = next;
    }
  }
  const [n, p] = arg(bytes, pos, info);
  pos = p;
  for (let i = 0n; i < n; i++) {
    const [v, next] = item(bytes, pos);
    items.push(v);
    pos = next;
  }
  return [items, pos];
}

function item(bytes, pos) {
  if (pos >= bytes.length) throw new Error('truncated');
  const ib = bytes[pos];
  const major = ib >> 5;
  const info = ib & 31;
  pos += 1;
  switch (major) {
    case 0: return arg(bytes, pos, info);
    case 1: { const [n, p] = arg(bytes, pos, info); return [-1n - n, p]; }
    case 2: return byteString(bytes, pos, info);
    case 4: return list(bytes, pos, info);
    case 5: {
      const [n, p] = arg(bytes, pos, info);
      pos = p;
      const entries = [];
      for (let i = 0n; i < n; i++) {
        const [k, p1] = item(bytes, pos);
        const [v, p2] = item(bytes, p1);
        entries.push([k, v]);
        pos = p2;
      }
      return [{ map: entries }, pos];
    }
    case 6: {
      const [tag, p] = arg(bytes, pos, info);
      if (tag === 2n || tag === 3n) {
        if (p >= bytes.length || bytes[p] >> 5 !== 2) throw new Error('bad bignum');
        const [b, next] = byteString(bytes, p + 1, bytes[p] & 31);
        let v = 0n;
        for (const x of b) v = (v << 8n) | BigInt(x);
        return [tag === 2n ? v : -1n - v, next];
      }
      if (tag >= 121n && tag <= 127n) {
        const [fields, next] = item(bytes, p);
        if (!Array.isArray(fields)) throw new Error('bad constructor');
        return [{ constr: Number(tag - 121n), fields }, next];
      }
      if (tag >= 1280n && tag <= 1400n) {
        const [fields, next] = item(bytes, p);
        if (!Array.isArray(fields)) throw new Error('bad constructor');
        return [{ constr: Number(tag - 1280n + 7n), fields }, next];
      }
      if (tag === 102n) {
        const [pair, next] = item(bytes, p);
        if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'bigint' || !Array.isArray(pair[1])) {
          throw new Error('bad constructor');
        }
        return [{ constr: Number(pair[0]), fields: pair[1] }, next];
      }
      throw new Error('unsupported tag ' + tag);
    }
    default:
      throw new Error('unsupported CBOR major type ' + major);
  }
}
