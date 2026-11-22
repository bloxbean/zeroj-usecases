// The customer's inclusion check against the chain (ADR-0009 D4.3), the browser twin of
// CustomerCheck.java. Both run src/test/resources/customer-check-fixtures.json.
//
// 1. Recompute the root from id, salt, balance, leaf index and path (in this browser).
// 2. Current period from the indexer's latest block time and the pinned genesisMs / periodMs.
// 3. Exactly one unspent output holding policyId || I2OSP8(period), at the script's enterprise
//    address, with inline datum Attestation(period, root, totalLiabilities, totalReserves).
// 4. The token's whole mint history, page by page from 1: exactly one mint of 1, no burn. An
//    unavailable, inconsistent or over-long history fails closed.
// 5. Compare the attested root with the recomputed one.
import { bech32Decode } from './bech32.js';
import { decodePlutusData, hexToBytes } from './cbor.js';
import { P } from './poseidon.js';
import { recomputeRoot, SALT_BITS } from './leaves.js';

export const HISTORY_PAGE_SIZE = 100;
export const MAX_HISTORY_PAGES = 20;
export const MAX_DEPTH = 32;
const UINT64 = 1n << 64n;

export const Outcome = Object.freeze({
  VERIFIED: 'VERIFIED',
  BAD_INPUT: 'BAD_INPUT',
  INDEXER_UNAVAILABLE: 'INDEXER_UNAVAILABLE',
  BEFORE_GENESIS: 'BEFORE_GENESIS',
  NO_ATTESTATION: 'NO_ATTESTATION',
  DUPLICATE_ATTESTATION: 'DUPLICATE_ATTESTATION',
  NOT_AT_SCRIPT_ADDRESS: 'NOT_AT_SCRIPT_ADDRESS',
  BAD_DATUM: 'BAD_DATUM',
  WRONG_PERIOD: 'WRONG_PERIOD',
  HISTORY_INCOMPLETE: 'HISTORY_INCOMPLETE',
  ROOT_MISMATCH: 'ROOT_MISMATCH',
});

/** policyId || hex(I2OSP8(period)). */
export function unitOf(policyId, period) {
  return policyId + BigInt(period).toString(16).padStart(16, '0');
}

const result = (outcome, detail, extra = {}) => ({ outcome, detail, verified: outcome === Outcome.VERIFIED, ...extra });

function toBig(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === 'string' && /^-?[0-9]+$/.test(v)) return BigInt(v);
  throw new Error('not an integer');
}

function normalize(inclusion, deployment) {
  const d = {
    policyId: deployment?.policyId,
    genesisMs: toBig(deployment?.genesisMs),
    periodMs: toBig(deployment?.periodMs),
  };
  if (typeof d.policyId !== 'string' || !/^[0-9a-f]{56}$/.test(d.policyId)) throw new Error('policy id must be 56 lowercase hex characters');
  if (d.genesisMs < 0n || d.periodMs <= 0n) throw new Error('invalid attestation clock');
  const siblings = (inclusion?.siblings ?? []).map(toBig);
  const inc = {
    accountId: inclusion?.accountId,
    salt: toBig(inclusion?.salt),
    balance: toBig(inclusion?.balance),
    leafIndex: toBig(inclusion?.leafIndex),
    siblings,
  };
  if (typeof inc.accountId !== 'string') throw new Error('missing account id');
  if (inc.salt < 0n || inc.salt >= 1n << BigInt(SALT_BITS)) throw new Error('invalid salt');
  if (inc.balance < 0n || inc.balance >= UINT64) throw new Error('invalid balance');
  if (siblings.length === 0 || siblings.length > MAX_DEPTH) throw new Error('invalid path length');
  if (siblings.some((s) => s < 0n || s >= P)) throw new Error('invalid sibling');
  if (inc.leafIndex < 0n || inc.leafIndex >= 1n << BigInt(siblings.length)) throw new Error('leaf index out of range');
  return { inc, d };
}

/** Header type 7 (script payment credential, no stake credential) and the policy id as the hash. */
export function atScriptAddress(bech32, policyId) {
  try {
    const { bytes } = bech32Decode(bech32);
    if (bytes.length !== 29 || bytes[0] >> 4 !== 7) return false;
    const hash = hexToBytes(policyId);
    return hash.every((b, i) => bytes[i + 1] === b);
  } catch {
    return false;
  }
}

/** Attestation(period, liabilitiesRoot, totalLiabilities, totalReserves) with the validator's ranges, or null. */
export function decodeAttestation(hex) {
  if (typeof hex !== 'string' || hex.length === 0) return null;
  try {
    const d = decodePlutusData(hex);
    if (!d || d.constr !== 0 || d.fields.length !== 4 || !d.fields.every((f) => typeof f === 'bigint')) return null;
    const [period, liabilitiesRoot, totalLiabilities, totalReserves] = d.fields;
    const u64 = (v) => v >= 0n && v < UINT64;
    if (!u64(period) || period >= 1n << 63n || liabilitiesRoot < 0n || liabilitiesRoot >= P || !u64(totalLiabilities) || !u64(totalReserves)) {
      return null;
    }
    return { period, liabilitiesRoot, totalLiabilities, totalReserves };
  } catch {
    return null;
  }
}

async function history(indexer, unit, pageSize) {
  let mints = 0;
  let burns = 0;
  let minted = 0n;
  let complete = false;
  try {
    for (let page = 1; page <= MAX_HISTORY_PAGES; page++) {
      const entries = await indexer.assetHistory(unit, page, pageSize);
      if (!Array.isArray(entries) || entries.length > pageSize) return Outcome.HISTORY_INCOMPLETE;
      for (const e of entries) {
        const q = e == null ? 0n : toBig(e.quantity);
        if (q === 0n || (e.unit != null && e.unit !== unit)) return Outcome.HISTORY_INCOMPLETE;
        if (q > 0n) { mints++; minted += q; } else { burns++; }
      }
      if (entries.length < pageSize) { complete = true; break; }
    }
  } catch {
    return Outcome.HISTORY_INCOMPLETE;
  }
  if (!complete || mints === 0) return Outcome.HISTORY_INCOMPLETE;
  if (mints !== 1 || minted !== 1n || burns !== 0) return Outcome.DUPLICATE_ATTESTATION;
  return Outcome.VERIFIED;
}

/**
 * @param inclusion  { accountId, salt, balance, leafIndex, siblings } (decimal strings or bigints)
 * @param deployment { policyId, genesisMs, periodMs }, pinned by the customer
 * @param indexer    { latestBlockTimeMs(), assetUtxos(unit, count), assetHistory(unit, page, count) }
 */
export async function check(inclusion, deployment, indexer, pageSize = HISTORY_PAGE_SIZE) {
  let inc, d;
  try {
    ({ inc, d } = normalize(inclusion, deployment));
  } catch (e) {
    return result(Outcome.BAD_INPUT, e.message);
  }
  const root = recomputeRoot(inc);

  let now;
  try {
    now = toBig(await indexer.latestBlockTimeMs());
  } catch (e) {
    return result(Outcome.INDEXER_UNAVAILABLE, 'chain time: ' + e.message, { root });
  }
  if (now < d.genesisMs) return result(Outcome.BEFORE_GENESIS, 'no period has started', { root });
  const period = (now - d.genesisMs) / d.periodMs;
  const unit = unitOf(d.policyId, period);

  let utxos;
  try {
    utxos = await indexer.assetUtxos(unit, HISTORY_PAGE_SIZE);
  } catch (e) {
    return result(Outcome.INDEXER_UNAVAILABLE, 'token outputs: ' + e.message, { root, period });
  }
  if (!Array.isArray(utxos) || utxos.length === 0) {
    return result(Outcome.NO_ATTESTATION, `no attestation token for period ${period}`, { root, period });
  }
  if (utxos.length !== 1) {
    return result(Outcome.DUPLICATE_ATTESTATION, `${utxos.length} outputs hold the period's token`, { root, period });
  }
  const utxo = utxos[0];
  let held;
  try { held = toBig(utxo.amounts?.[unit]); } catch { held = null; }
  if (held !== 1n) {
    return result(Outcome.DUPLICATE_ATTESTATION, `the output holds ${held} of the token`, { root, period });
  }
  if (!atScriptAddress(utxo.address, d.policyId)) {
    return result(Outcome.NOT_AT_SCRIPT_ADDRESS, 'token output is not at the attestation script address', { root, period });
  }
  const attestation = decodeAttestation(utxo.inlineDatum);
  if (!attestation) return result(Outcome.BAD_DATUM, 'the inline datum is not an Attestation', { root, period });
  if (attestation.period !== period) {
    return result(Outcome.WRONG_PERIOD, `datum period ${attestation.period} != ${period}`, { root, period, attestation });
  }

  const h = await history(indexer, unit, pageSize);
  if (h !== Outcome.VERIFIED) {
    const detail = h === Outcome.DUPLICATE_ATTESTATION
      ? "the period's token was minted more than once"
      : "the token's mint history is unavailable or incomplete";
    return result(h, detail, { root, period, attestation, txHash: utxo.txHash });
  }
  if (attestation.liabilitiesRoot !== root) {
    return result(Outcome.ROOT_MISMATCH, 'the attested root differs from your recomputed root', { root, period, attestation, txHash: utxo.txHash });
  }
  return result(Outcome.VERIFIED, `included in the attested tree for period ${period}`, { root, period, attestation, txHash: utxo.txHash });
}
