// Salted leaves (ADR-0009 D4.1), mirroring ReserveLeaves.java:
//   idTag    = fold(Poseidon2, tag("zeroj.reserves.id.v1"), [len, c_0, ..., c_k])
//   saltedId = Poseidon2(idTag, salt)
//   leaf     = Poseidon2(saltedId, balance)
// len is the UTF-8 byte length; c_i are 31-byte big-endian chunks, the last right-padded with zeros.
import { poseidon2 } from './poseidon.js';

/** tag("zeroj.reserves.id.v1"): blake2b-256 with its top byte cleared (vector-checked in frontend/test). */
export const ID_TAG_DOMAIN = 97099946153959407749691760725732336561268409594527988031182142979064634983n;
export const SALT_BITS = 252;
const CHUNK = 31;

function bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export function idTag(accountId) {
  const bytes = new TextEncoder().encode(accountId);
  let acc = poseidon2(ID_TAG_DOMAIN, BigInt(bytes.length));
  for (let off = 0; off < bytes.length; off += CHUNK) {
    const chunk = new Uint8Array(CHUNK); // zero-filled: right-pads the last chunk
    chunk.set(bytes.subarray(off, Math.min(off + CHUNK, bytes.length)));
    acc = poseidon2(acc, bytesToBigInt(chunk));
  }
  return acc;
}

export function saltedId(accountId, salt) {
  if (salt < 0n || salt >= 1n << BigInt(SALT_BITS)) throw new Error('invalid salt');
  return poseidon2(idTag(accountId), salt);
}

export const leaf = (saltedIdValue, balance) => poseidon2(saltedIdValue, balance);
export const node = (left, right) => poseidon2(left, right);

/** Bit i of leafIndex says whether the node is the right child at level i. */
export function recomputeRoot({ accountId, salt, balance, leafIndex, siblings }) {
  let h = leaf(saltedId(accountId, salt), balance);
  let index = BigInt(leafIndex);
  for (const sibling of siblings) {
    h = (index & 1n) === 0n ? node(h, sibling) : node(sibling, h);
    index >>= 1n;
  }
  return h;
}
