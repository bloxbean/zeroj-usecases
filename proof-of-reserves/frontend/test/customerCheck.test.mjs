// The browser customer check against the fixtures CustomerCheckTest.java runs (ADR-0009 D4, M4):
// ZeroJ-produced Poseidon/idTag vectors, the recomputed root, and every check scenario.
// Run with: npm test (Node's built-in runner, no dependencies).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ID_TAG_DOMAIN, idTag, leaf, recomputeRoot, saltedId } from '../src/lib/reserves/leaves.js';
import { check } from '../src/lib/reserves/customerCheck.js';

const fixtures = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../src/test/resources/customer-check-fixtures.json', import.meta.url)), 'utf8'));

const fromHex = (hex) => new TextDecoder().decode(Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16)));

test('domain tag matches the ZeroJ vector', () => {
  assert.equal(ID_TAG_DOMAIN, BigInt(fixtures.vectors.idDomainTag));
});

test('idTag vectors: empty, 31 and 32 bytes, leading zero bytes, UTF-8', () => {
  assert.ok(fixtures.vectors.idTags.length >= 5);
  for (const v of fixtures.vectors.idTags) {
    assert.equal(idTag(fromHex(v.utf8Hex)), BigInt(v.idTag), `idTag(${v.utf8Hex})`);
  }
});

test('salted id and leaf match the ZeroJ vector', () => {
  const v = fixtures.vectors.leaf;
  const s = saltedId(v.accountId, BigInt(v.salt));
  assert.equal(s, BigInt(v.saltedId));
  assert.equal(leaf(s, BigInt(v.balance)), BigInt(v.leaf));
});

test('recomputed root matches the tree', () => {
  assert.equal(recomputeRoot({ ...fixtures.inclusion, salt: BigInt(fixtures.inclusion.salt),
    balance: BigInt(fixtures.inclusion.balance), siblings: fixtures.inclusion.siblings.map(BigInt) }), BigInt(fixtures.root));
});

function inclusion(override = {}) {
  const base = fixtures.inclusion;
  const siblings = base.siblings.map((s, i) => override['sibling' + i] ?? s);
  return {
    accountId: override.accountId ?? base.accountId,
    salt: override.salt ?? base.salt,
    balance: override.balance ?? base.balance,
    leafIndex: override.leafIndex ?? String(base.leafIndex),
    siblings,
  };
}

/** Serves a scenario's indexer data, as CustomerCheckTest.FixtureIndexer does. */
function fixtureIndexer(spec) {
  return {
    async latestBlockTimeMs() {
      if (spec.latestTimeMs == null) throw new Error('unavailable');
      return BigInt(spec.latestTimeMs);
    },
    async assetUtxos(unit) {
      if (spec.utxosError) throw new Error('unavailable');
      return (spec.utxos[unit] ?? []).map((u) => ({ ...u }));
    },
    async assetHistory(unit, page) {
      const h = spec.history[unit] ?? {};
      if (h.errorAtPage === page) throw new Error('unavailable');
      const pages = h.pages ?? [];
      return (h.repeat ? pages[0] : pages[page - 1] ?? []).map((e) => ({ ...e }));
    },
  };
}

for (const s of fixtures.scenarios) {
  test(`scenario: ${s.name}`, async () => {
    const r = await check(inclusion(s.override), fixtures.deployment, fixtureIndexer(s.indexer), s.pageSize);
    assert.equal(r.outcome, s.expected, r.detail);
  });
}
