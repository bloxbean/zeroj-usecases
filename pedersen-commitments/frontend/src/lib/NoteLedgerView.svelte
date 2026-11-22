<script lang="ts">
  // The shared state panels of a confidential-note ledger (points, payroll): what each wallet
  // recovers from the chain, what anyone sees on-chain, and what the auditor reads.
  let { state, unit = 'points' }: { state: any; unit?: string } = $props();
</script>

<div class="columns">
  <div class="panel private">
    <h3>Wallets — recovered from the chain with each viewing key</h3>
    {#each Object.entries(state.wallets) as [label, w]}
      <p><strong>{label}</strong>: balance <strong>{w.balance}</strong> {unit}
        {#if w.unopenable.length > 0}<span class="pill bad">{w.unopenable.length} unopenable owned note{w.unopenable.length > 1 ? 's' : ''}</span>{/if}
        {#if w.readableNotMine > 0}<span class="pill">{w.readableNotMine} readable, not owned</span>{/if}
      </p>
      {#if w.notes.length > 0}
        <table>
          <thead><tr><th>amount</th><th>commitment (u)</th><th>gen</th><th>note UTxO</th></tr></thead>
          <tbody>
            {#each w.notes as n}<tr><td>{n.amount}</td><td><code>{n.commitment}</code></td><td>{n.generation}</td><td><code>{n.utxo}</code></td></tr>{/each}
          </tbody>
        </table>
      {/if}
      {#each w.unopenable as u}<p class="hint bad">Owned but unopenable: <code>{u}</code> — the sender's delivery does not open to the commitment.</p>{/each}
    {/each}
  </div>

  <div class="panel public">
    <h3>On-chain — what anyone can see</h3>
    <p class="hint">Notes at <code>{state.ledgerAddress.substring(0, 34)}…</code>: owner, commitment, generation, two limb
      ciphertexts and two encrypted openings — never the amount.</p>
    <table>
      <thead><tr><th>note UTxO</th><th>owner</th><th>commitment u</th><th>gen</th><th>limb A.u</th><th>deliveries</th></tr></thead>
      <tbody>
        {#each state.onChain as n}<tr><td><code>{n.utxo}</code></td><td>{n.owner}</td><td><code>{n.u}</code></td><td>{n.generation}</td><td><code>{n.limbHandle}</code></td><td>{n.deliveries} × 89 B</td></tr>{/each}
      </tbody>
    </table>
    {#if state.receipts.length > 0}
      <h3>Receipts held by the issuer</h3>
      <table>
        <thead><tr><th>receipt UTxO</th><th>spender</th><th>price</th></tr></thead>
        <tbody>
          {#each state.receipts as r}<tr><td><code>{r.utxo}</code></td><td>{r.spender}</td><td>{r.price}</td></tr>{/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<div class="panel auditor">
  <h3>{state.auditor.label} — reads every amount from the chain</h3>
  <p class="hint">Registry generation <strong>{state.registry.generation}</strong> · ElGamal key <code>{state.registry.elgamalKey}</code>
    · viewing key <code>{state.registry.viewingKey}</code>. Amounts come from the limb ciphertexts (keys of the note's generation);
    each is cross-checked against the auditor's own encrypted opening.</p>
  <table>
    <thead><tr><th>note UTxO</th><th>owner</th><th>amount</th><th>origin</th><th>gen</th><th>check</th></tr></thead>
    <tbody>
      {#each state.auditor.notes as a}
        <tr class:bad={!a.consistent}>
          <td><code>{a.utxo}</code></td><td>{a.owner}</td><td><strong>{a.amount}</strong></td>
          <td><span class="pill" class:ok={a.origin === 'proof-enforced'}>{a.origin}</span></td>
          <td>{a.generation}</td><td>{a.status}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  <p class="hint">Totals by owner:
    {#each Object.entries(state.auditor.totals) as [owner, total], i}{i > 0 ? ' · ' : ''}{owner} {total}{/each}</p>
</div>

{#if state.history.length > 0}
  <h3>Transactions</h3>
  <table>
    <tbody>
      {#each state.history as h}<tr><td>{h.summary}</td><td>{h.cost ?? ''}</td><td><code>{h.txHash.substring(0, 20)}…</code></td></tr>{/each}
    </tbody>
  </table>
{/if}

<style>
  .auditor { margin-top: 1rem; }
  .pill { display: inline-block; padding: 0 0.4rem; border-radius: 0.6rem; background: #e5e7eb; font-size: 0.8rem; margin-left: 0.3rem; }
  .pill.ok { background: #d1fae5; }
  .pill.bad, tr.bad td { color: #b91c1c; }
  p.bad { color: #b91c1c; }
</style>
