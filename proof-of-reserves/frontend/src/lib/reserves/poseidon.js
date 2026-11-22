// Poseidon over BLS12-381 Fr, t = 3, alpha = 5: the browser copy of ZeroJ's PoseidonHash.hash
// (state [0, a, b], output state[0]). Constants come from ZeroJ via poseidonParams.js, and
// frontend/test checks outputs against vectors produced by ZeroJ.
import params from './poseidonParams.js';

export const P = BigInt(params.prime);
const T = params.t;
const RF = params.rf;
const RP = params.rp;
const C = params.c.map(BigInt);
const M = params.m.map(BigInt);

if (T !== 3 || params.alpha !== 5 || C.length !== (RF + RP) * T || M.length !== T * T) {
  throw new Error('unexpected Poseidon parameters');
}

const mod = (x) => ((x % P) + P) % P;

function sbox(x) {
  const x2 = (x * x) % P;
  const x4 = (x2 * x2) % P;
  return (x4 * x) % P;
}

/** Poseidon2(a, b) for non-negative bigint inputs (reduced mod p on entry). */
export function poseidon2(a, b) {
  let s = [0n, mod(a), mod(b)];
  for (let r = 0; r < RF + RP; r++) {
    for (let i = 0; i < T; i++) s[i] = (s[i] + C[r * T + i]) % P;
    if (r < RF / 2 || r >= RF / 2 + RP) {
      for (let i = 0; i < T; i++) s[i] = sbox(s[i]);
    } else {
      s[0] = sbox(s[0]);
    }
    const next = [0n, 0n, 0n];
    for (let i = 0; i < T; i++) {
      let acc = 0n;
      for (let j = 0; j < T; j++) acc += M[i * T + j] * s[j];
      next[i] = acc % P;
    }
    s = next;
  }
  return s[0];
}
