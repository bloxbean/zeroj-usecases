<script lang="ts">
  import { get, post } from '../lib/api';
  import Outcome from '../lib/Outcome.svelte';

  let state = $state<any>(null);
  let busy = $state('');
  let result = $state<any>(null);

  let issueTo = $state('alice');
  let issueAmount = $state(1000);
  let from = $state('alice');
  let to = $state('bob');
  let amount = $state(700);
  let redeemFrom = $state('bob');
  let price = $state(120);
  let thief = $state('bob');
  let victim = $state('alice');

  const holders = ['alice', 'bob', 'retailer'];

  async function load() {
    const r = await get('/points');
    if (r.ok) state = r.data;
  }

  async function act(label: string, path: string, body: unknown) {
    busy = label;
    result = null;
    result = await post(path, body);
    busy = '';
    await load();
  }

  $effect(() => { load(); });
</script>

<section>
  <h2>A. Confidential points</h2>
  <p class="hint">Loyalty points are notes whose amounts are Pedersen commitments. A transfer proves
    <code>in = out1 + out2</code> over hidden 64-bit amounts; a redemption proves <code>in = change + price</code>
    with a public price. The <code>PointsLedger</code> script checks the proof, the owner's signature, issuer-only
    supply and one-time receipts. Circuits: transfer {state?.constraints?.transfer ?? '…'} constraints, redeem
    {state?.constraints?.redeem ?? '…'}.</p>

  <div class="actions">
    <div class="action">
      <h4>Issue (retailer)</h4>
      <label>to <select bind:value={issueTo}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <label>amount <input type="number" min="1" bind:value={issueAmount} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Issuing', '/points/issue', { to: issueTo, amount: issueAmount })}>Issue</button>
    </div>
    <div class="action">
      <h4>Transfer</h4>
      <label>from <select bind:value={from}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <label>to <select bind:value={to}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <label>amount <input type="number" min="1" bind:value={amount} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Proving and submitting the transfer', '/points/transfer', { from, to, amount })}>Transfer</button>
      <p class="hint">Cheat: ask for more than the sender's largest note holds — no proof exists.</p>
    </div>
    <div class="action">
      <h4>Redeem at the retailer</h4>
      <label>from <select bind:value={redeemFrom}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <label>price (public) <input type="number" min="1" bind:value={price} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Proving and submitting the redemption', '/points/redeem', { from: redeemFrom, price })}>Redeem</button>
    </div>
    <div class="action cheat">
      <h4>Try to cheat: spend someone else's note</h4>
      <label>thief <select bind:value={thief}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <label>victim <select bind:value={victim}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <button class="danger" disabled={!!busy} onclick={() => act('Submitting the theft', '/points/steal', { thief, victim })}>Steal the largest note</button>
      <p class="hint">Even with a valid proof, the script requires the note owner's signature.</p>
    </div>
  </div>

  {#if busy}<p class="busy">{busy}… (proving and waiting for the block)</p>{/if}
  <Outcome {result} />

  {#if state}
    <div class="columns">
      <div class="panel private">
        <h3>Private — the openings each wallet holds</h3>
        {#each Object.entries(state.private) as [label, w]}
          <p><strong>{label}</strong>: balance <strong>{w.balance}</strong> points</p>
          {#if w.notes.length > 0}
            <table>
              <thead><tr><th>amount</th><th>commitment (u)</th><th>note UTxO</th></tr></thead>
              <tbody>
                {#each w.notes as n}<tr><td>{n.amount}</td><td><code>{n.commitment}</code></td><td><code>{n.utxo}</code></td></tr>{/each}
              </tbody>
            </table>
          {/if}
        {/each}
      </div>
      <div class="panel public">
        <h3>On-chain — what anyone can see</h3>
        <p class="hint">Notes at <code>{state.ledgerAddress.substring(0, 34)}…</code>: owner and commitment, never the amount.</p>
        <table>
          <thead><tr><th>note UTxO</th><th>owner</th><th>commitment u</th><th>v</th></tr></thead>
          <tbody>
            {#each state.onChain as n}<tr><td><code>{n.utxo}</code></td><td>{n.owner}</td><td><code>{n.u}</code></td><td><code>{n.v}</code></td></tr>{/each}
          </tbody>
        </table>
        <h3>Receipts held by the retailer</h3>
        {#if state.receipts.length === 0}<p class="hint">None yet.</p>{/if}
        <table>
          {#if state.receipts.length > 0}<thead><tr><th>receipt UTxO</th><th>spender</th><th>price</th></tr></thead>{/if}
          <tbody>
            {#each state.receipts as r}<tr><td><code>{r.utxo}</code></td><td>{r.spender}</td><td>{r.price}</td></tr>{/each}
          </tbody>
        </table>
      </div>
    </div>

    {#if state.history.length > 0}
      <h3>Transactions</h3>
      <table>
        <tbody>
          {#each state.history as h}<tr><td>{h.summary}</td><td><code>{h.txHash.substring(0, 20)}…</code></td></tr>{/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>
