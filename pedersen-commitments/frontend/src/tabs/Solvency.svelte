<script lang="ts">
  import { get, post } from '../lib/api';
  import Outcome from '../lib/Outcome.svelte';

  let state = $state<any>(null);
  let busy = $state('');
  let result = $state<any>(null);
  let reservesAda = $state(2000);
  let garbageFor = $state('dave');
  let rows = $state<{ id: string; balance: number }[]>([]);
  let offset = 0;            // chain time − local time, from the last state fetch
  let now = $state(Date.now());

  async function load() {
    const r = await get('/solvency');
    if (r.ok) {
      state = r.data;
      offset = r.data.chainTime - Date.now();
      if (rows.length === 0) rows = r.data.book.map((c: any) => ({ id: c.id, balance: c.balance }));
    }
  }

  async function act(label: string, path: string, body: unknown = {}) {
    busy = label;
    result = null;
    result = await post(path, body);
    busy = '';
    await load();
  }

  function seconds(target: number) {
    return Math.max(0, Math.round((target - (now + offset)) / 1000));
  }

  $effect(() => {
    load();
    const tick = setInterval(() => { now = Date.now(); }, 1000);
    const refresh = setInterval(() => { if (!busy && state?.period) load(); }, 5000);
    return () => { clearInterval(tick); clearInterval(refresh); };
  });

  let live = $derived(state?.period && !state?.releaseTx);
</script>

<section>
  <h2>C. Hidden-liability solvency</h2>
  <p class="hint">The exchange publishes one Pedersen commitment per customer balance and proves
    <code>Σ balances ≤ reserves</code> while hiding every balance and the total. The reserve is locked in a vault for a
    public <em>attestation period</em>: attestations only before it starts, release only after it ends, so the same funds
    cannot back attestations one after another. Each entry carries its customer's opening <strong>encrypted on-chain</strong>
    to the customer's viewing key, and the attestation carries the total's opening encrypted to the auditor's registered
    viewing key (<code>confidential-note-jubjub-v1</code>): customers and the auditor check from the chain alone, and an
    entry the customer cannot open is on-chain evidence against the exchange. Circuit: {state?.constraints ?? '…'}
    constraints (4 customers).</p>

  <div class="actions">
    <div class="action">
      <h4>1. The book (balances in ADA)</h4>
      <table>
        <tbody>
          {#each rows as r}
            <tr><td><input bind:value={r.id} disabled={live} /></td><td><input type="number" min="0" bind:value={r.balance} disabled={live} /></td></tr>
          {/each}
        </tbody>
      </table>
      <button class="primary" disabled={!!busy || live} onclick={() => act('Saving the book', '/solvency/book', { customers: rows })}>Save book</button>
    </div>
    <div class="action">
      <h4>2. Attest for a new period</h4>
      <label>reserves to lock (ADA) <input type="number" min="1" bind:value={reservesAda} disabled={live} /></label>
      <button class="primary" disabled={!!busy || live} onclick={() => act('Proving solvency and locking the reserve', '/solvency/attest', { reservesAda })}>Attest</button>
      <p class="hint">Lock less than the book's total to see that no proof exists.</p>
    </div>
    <div class="action">
      <h4>3. Check (during the period)</h4>
      {#each state?.book ?? [] as c}
        <button class="primary" disabled={!!busy || !state?.period} onclick={() => act(`${c.id} checks the attestations`, '/solvency/check', { id: c.id })}>{c.id} checks</button>
      {/each}
      <button class="primary" disabled={!!busy || !state?.period} onclick={() => act('Auditor opens the total', '/solvency/audit')}>Auditor opens the total</button>
    </div>
    <div class="action cheat">
      <h4>Attest with a garbage delivery</h4>
      <label>for <select bind:value={garbageFor}>{#each state?.book ?? [] as c}<option>{c.id}</option>{/each}</select></label>
      <p class="hint">The exchange attests honestly but gives {garbageFor} an encrypted opening that does not open. The vault can
        only check its length; {garbageFor}'s check reports it as unopenable.</p>
      <button class="danger" disabled={!!busy || live} onclick={() => act('Proving solvency and attesting with a garbage delivery', '/solvency/attest', { reservesAda, garbageFor })}>Attest with garbage</button>
    </div>
    <div class="action cheat">
      <h4>Try to cheat inside the period</h4>
      <button class="danger" disabled={!!busy || !live} onclick={() => act('Submitting another attestation', '/solvency/attest-again')}>Attest again</button>
      <button class="danger" disabled={!!busy || !live} onclick={() => act('Releasing the reserve', '/solvency/release')}>Release the reserve</button>
      <p class="hint">Before the period ends the vault rejects a release; after it ends the release succeeds.</p>
    </div>
  </div>

  {#if busy}<p class="busy">{busy}… (proving and waiting for the block)</p>{/if}
  <Outcome {result} />
  {#if result?.ok && result.data.liabilitiesAda !== undefined}
    <div class="card">Auditor: its on-chain delivery opens, against the sum of all on-chain commitments, to total liabilities of
      <strong>{result.data.liabilitiesAda} ADA</strong> against {result.data.reservesAda} ADA locked —
      {result.data.ok ? 'verified' : 'NOT verified'}. No single balance is revealed.</div>
  {/if}

  {#if state}
    {#if state.period}
      <div class="card">
        <strong>Period:</strong> phase <strong>{state.phase}</strong>
        {#if state.phase === 'before'} — starts in {seconds(state.period.start)} s (attestations allowed until then){/if}
        {#if state.phase === 'during'} — ends in {seconds(state.period.end)} s (nothing can be added or released){/if}
        {#if state.phase === 'after'} — ended; the reserve can be released{/if}
        {#if state.phase === 'released'} — reserve released, tx <code>{state.releaseTx.substring(0, 20)}…</code>{/if}
      </div>
    {/if}
    <div class="columns">
      <div class="panel private">
        <h3>Private — the exchange's book (customers recover their own opening from the chain)</h3>
        <p>Total liabilities: <strong>{state.liabilitiesAda} ADA</strong> (never published)</p>
        <table>
          <thead><tr><th>customer</th><th>balance</th><th>salt</th><th>blinding</th><th>id hash</th><th>last check</th></tr></thead>
          <tbody>
            {#each state.book as c}
              <tr><td>{c.id}</td><td>{c.balance}</td><td><code>{c.salt}</code></td><td><code>{c.blinding}</code></td><td><code>{c.idHash}</code></td><td>{c.check}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="panel public">
        <h3>On-chain — the period's vault</h3>
        {#if state.period}
          <p>Reserve locked: <strong>{state.reservesAda} ADA</strong> at <code>{state.vaultAddress.substring(0, 30)}…</code></p>
          <table>
            <thead><tr><th>id hash</th><th>commitment u</th><th>encrypted opening</th></tr></thead>
            <tbody>
              {#each state.onChain ?? [] as e}<tr><td><code>{e.idHash}</code></td><td><code>{e.u}</code></td><td><code>{e.delivery}</code></td></tr>{/each}
            </tbody>
          </table>
          <p class="hint">Attestation tx <code>{state.attestTx.substring(0, 20)}…</code></p>
        {:else}<p class="hint">No attestation yet.</p>{/if}
      </div>
    </div>
  {/if}
</section>
