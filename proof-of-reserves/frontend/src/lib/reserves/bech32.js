// Bech32 (BIP-173) decoding for Cardano addresses, which are longer than BIP-173's 90 characters.
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

/** Returns { hrp, bytes }, or throws on a bad checksum, mixed case or bad padding. */
export function bech32Decode(str) {
  if (typeof str !== 'string' || str.length > 200) throw new Error('bad bech32');
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) throw new Error('mixed case');
  const s = str.toLowerCase();
  const sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length) throw new Error('bad bech32');
  const hrp = s.slice(0, sep);
  const data = [];
  for (const c of s.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error('bad bech32 character');
    data.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error('bad bech32 checksum');
  const words = data.slice(0, -6);
  let acc = 0;
  let bits = 0;
  const bytes = [];
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 0xff);
    }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff) !== 0) throw new Error('bad bech32 padding');
  return { hrp, bytes: Uint8Array.from(bytes) };
}
