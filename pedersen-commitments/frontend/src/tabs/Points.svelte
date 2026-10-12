<script lang="ts">
  import { get, post } from '../lib/api';
  import Outcome from '../lib/Outcome.svelte';
  import NoteLedgerView from '../lib/NoteLedgerView.svelte';

  let state = $state<any>(null);
  let busy = $state('');
  let result = $state<any>(null);

  let issueTo = $state('alice');
  let issueAmount = $state(1000);
  let reported = $state(100);
  let from = $state('alice');
  let to = $state('bob');
  let amount = $state(700);
  let redeemFrom = $state('bob');
  let price = $state(120);
  let thief = $state('bob');
  let victim = $state('alice');

  const holders = ['alice', 'bob'];

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
  <p class="hint">Loyalty points are <strong>notes</strong>: a Pedersen commitment, the opening encrypted on-chain to the
    owner and the auditor (<code>confidential-note-jubjub-v1</code>), and the amount encrypted to the auditor as two
    32-bit ElGamal limbs that the transfer proof binds to the commitment (ADR-0055 D3a). Wallets recover their notes by
    scanning the chain with their viewing key; the auditor reads every amount from the chain. Issuance is
    <em>trusted</em>: the retailer supplies the issued notes' audit data. Circuits: transfer
    {state?.constraints?.transfer ?? '…'} constraints, redeem {state?.constraints?.redeem ?? '…'}.</p>

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
    <div class="action">
      <h4>Auditor key rotation</h4>
      <p class="hint">Registry generation {state?.registry?.generation ?? '…'}. Both possession proofs are verified on-chain.</p>
      <button disabled={!!busy} onclick={() => act('Rotating the auditor keys', '/points/rotate', {})}>Rotate auditor keys</button>
    </div>
  </div>

  <h3>Try to cheat</h3>
  <div class="actions">
    <div class="action cheat">
      <h4>Garbage delivery</h4>
      <p class="hint">{from} sends {amount} to {to}, but the recipient's encrypted opening is random bytes. The ledger
        can only check its length, so it is accepted: {to}'s wallet reports an <em>unopenable</em> note, while the auditor
        still reads the amount (D3a).</p>
      <button class="danger" disabled={!!busy} onclick={() => act('Submitting a transfer with a garbage delivery', '/points/transfer', { from, to, amount, cheat: 'garbageDelivery' })}>Send with garbage delivery</button>
    </div>
    <div class="action cheat">
      <h4>Under-report an issuance</h4>
      <label>tell the auditor <input type="number" min="0" bind:value={reported} /></label>
      <p class="hint">The retailer issues {issueAmount} but encrypts {reported} to the auditor. Trusted issuance accepts it;
        the auditor sees <em>issuer-claimed</em> and a mismatch with its own delivery. (Payroll's proved issuance refuses this.)</p>
      <button class="danger" disabled={!!busy} onclick={() => act('Issuing with under-reported audit data', '/points/issue', { to: issueTo, amount: issueAmount, reported })}>Issue and under-report</button>
    </div>
    <div class="action cheat">
      <h4>Limbs to the retired key</h4>
      <p class="hint">After a rotation, {from} encrypts the amounts to the auditor's previous key. The ledger reads the key
        from the current registry entry, so the proof does not verify.</p>
      <button class="danger" disabled={!!busy || !state?.canUseRetiredKey} onclick={() => act('Submitting a transfer to the retired key', '/points/transfer', { from, to, amount, cheat: 'retiredKey' })}>Use the retired key</button>
    </div>
    <div class="action cheat">
      <h4>Note under another stake key</h4>
      <p class="hint">An honest transfer plus a copy of a note paid to the ledger's script with another stake credential.
        The address policy refuses every output under the script that is not at its exact address (M3 criterion (a)).</p>
      <button class="danger" disabled={!!busy} onclick={() => act('Submitting a transfer with a stake-variant note', '/points/transfer', { from, to, amount, cheat: 'stakeVariant' })}>Add a stake-variant note</button>
    </div>
    <div class="action cheat">
      <h4>Spend someone else's note</h4>
      <label>thief <select bind:value={thief}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <label>victim <select bind:value={victim}>{#each holders as h}<option>{h}</option>{/each}</select></label>
      <button class="danger" disabled={!!busy} onclick={() => act('Submitting the theft', '/points/steal', { thief, victim })}>Steal the largest note</button>
    </div>
  </div>

  {#if busy}<p class="busy">{busy}… (proving and waiting for the block)</p>{/if}
  <Outcome {result} />

  {#if state}
    <NoteLedgerView {state} unit="points" />
  {/if}
</section>
