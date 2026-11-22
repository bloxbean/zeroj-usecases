<script lang="ts">
  import { get, post } from '../lib/api';
  import Outcome from '../lib/Outcome.svelte';

  let state = $state<any>(null);
  let busy = $state('');
  let result = $state<any>(null);
  let offset = 0;
  let now = $state(Date.now());

  let item = $state('Painting');
  let deposit = $state(100);
  let reserve = $state(10);
  let bidder = $state('alice');
  let amount = $state(40);
  let copier = $state('carol');
  let copied = $state('alice');
  let claimWinner = $state(1);

  const bidders = ['alice', 'bob', 'carol'];

  async function load() {
    const r = await get('/auction');
    if (r.ok) {
      state = r.data;
      offset = r.data.chainTime - Date.now();
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
    const refresh = setInterval(() => { if (!busy && state?.lot) load(); }, 6000);
    return () => { clearInterval(tick); clearInterval(refresh); };
  });

  let phase = $derived(!state?.lot ? 'none'
    : (now + offset) < state.lot.biddingEnds ? 'bidding'
    : (now + offset) < state.lot.settleBy ? 'settling' : 'expired');
</script>

<section>
  <h2>Sealed-bid auction</h2>
  <p class="hint">Each bid is encrypted to the auctioneer (<code>elgamal-jubjub-v1</code>) with a Groth16 proof that it
    lies between the reserve and the deposit, so a bidder <strong>cannot refuse to reveal</strong> its bid — there is no
    reveal phase. Everyone locks the same public deposit. After the bidding window the auctioneer decrypts every bid and
    proves, in zero knowledge, who placed the earliest highest bid and its amount, without publishing the losing bids.
    If it never settles, anyone can return the deposits and the item. Circuits: bid {state?.constraints?.bid ?? '…'}
    constraints, settlement of 3 bids {state?.constraints?.settle3 ?? '…'}.</p>

  <div class="actions">
    <div class="action">
      <h4>1. Seller lists an item</h4>
      <label>item <input bind:value={item} /></label>
      <label>deposit (ADA) <input type="number" min="2" bind:value={deposit} /></label>
      <label>reserve (ADA) <input type="number" min="2" bind:value={reserve} /></label>
      <button class="primary" disabled={!!busy || phase === 'bidding' || phase === 'settling'} onclick={() => act('Opening the lot', '/auction/open', { item, deposit, reserve })}>Open lot</button>
    </div>
    <div class="action">
      <h4>2. Sealed bid</h4>
      <label>bidder <select bind:value={bidder}>{#each bidders as b}<option>{b}</option>{/each}</select></label>
      <label>bid (ADA, hidden) <input type="number" min="0" bind:value={amount} /></label>
      <button class="primary" disabled={!!busy || phase !== 'bidding'} onclick={() => act('Proving and placing the bid', '/auction/bid', { bidder, amount })}>Bid</button>
      <p class="hint">Cheat: bid above the deposit or below the reserve — no proof exists.</p>
    </div>
    <div class="action">
      <h4>3. Auctioneer settles</h4>
      <button class="primary" disabled={!!busy || phase !== 'settling'} onclick={() => act('Decrypting the bids and proving the settlement', '/auction/settle', {})}>Settle</button>
      <button disabled={!!busy || phase !== 'expired'} onclick={() => act('Refunding after the deadline', '/auction/refund', {})}>Refund (after the deadline)</button>
      <button disabled={!!busy || phase === 'bidding' || phase === 'none'} onclick={() => act('Closing without bids', '/auction/no-bids', {})}>Close with no bids</button>
    </div>
  </div>

  <h3>Try to cheat</h3>
  <div class="actions">
    <div class="action cheat">
      <h4>Copy another bid</h4>
      <label>copier <select bind:value={copier}>{#each bidders as b}<option>{b}</option>{/each}</select></label>
      <label>copies <select bind:value={copied}>{#each bidders as b}<option>{b}</option>{/each}</select></label>
      <p class="hint">The copier submits a bid proof made for {copied}. The proof is bound to its bidder's key hash, so the
        lot refuses it.</p>
      <button class="danger" disabled={!!busy || phase !== 'bidding'} onclick={() => act('Submitting a copied bid', '/auction/bid', { bidder: copier, amount, copyFrom: copied })}>Submit a copied bid</button>
    </div>
    <div class="action cheat">
      <h4>Auctioneer names another winner</h4>
      <label>winner (bid #) <input type="number" min="1" max="3" bind:value={claimWinner} /></label>
      <p class="hint">The settlement proof shows the named bid is the earliest highest one; for any other bid no proof exists.</p>
      <button class="danger" disabled={!!busy || phase !== 'settling'} onclick={() => act('Proving a wrong settlement', '/auction/settle', { claimWinner })}>Settle for bid #{claimWinner}</button>
    </div>
  </div>

  {#if busy}<p class="busy">{busy}… (proving and waiting for the block)</p>{/if}
  <Outcome {result} />

  {#if state}
    {#if state.lot}
      <div class="card">
        <strong>Lot {state.lot.item}</strong> · deposit {state.lot.deposit} ADA · reserve {state.lot.reserve} ADA ·
        {#if phase === 'bidding'}bidding closes in <strong>{seconds(state.lot.biddingEnds)} s</strong>{/if}
        {#if phase === 'settling'}bidding closed; the auctioneer may settle for {seconds(state.lot.settleBy)} s{/if}
        {#if phase === 'expired'}settlement deadline passed: anyone can refund{/if}
      </div>
    {:else if state.closed}
      <div class="card">The last lot is closed (settled or refunded). Open a new one.</div>
    {/if}
    <div class="columns">
      <div class="panel public">
        <h3>On-chain — what anyone can see</h3>
        {#if state.lot}
          <p class="hint">Lot UTxO holding the item, {state.lot.lockedAda} ADA (deposits + lot ADA) and the lot token.
            Auctioneer key generation {state.lot.generation}.</p>
          <table>
            <thead><tr><th>#</th><th>bidder</th><th>handle A.u</th><th>ciphertext B.u</th></tr></thead>
            <tbody>
              {#each state.lot.bids as b, i}<tr><td>{i + 1}</td><td>{b.bidder}</td><td><code>{b.handle}</code></td><td><code>{b.ciphertext}</code></td></tr>{/each}
            </tbody>
          </table>
        {:else}<p class="hint">No open lot.</p>{/if}
        <h3>Balances</h3>
        <table>
          <tbody>{#each state.wallets as w}<tr><td>{w.wallet}</td><td>{w.ada} ADA</td></tr>{/each}</tbody>
        </table>
      </div>
      <div class="panel private">
        <h3>Auctioneer's private view — decrypted bids</h3>
        {#if state.auctioneerView && state.auctioneerView.length > 0}
          <table>
            <thead><tr><th>#</th><th>bidder</th><th>bid</th></tr></thead>
            <tbody>
              {#each state.auctioneerView as b, i}<tr><td>{i + 1}</td><td>{b.bidder}</td><td><strong>{b.amount}</strong> ADA</td></tr>{/each}
            </tbody>
          </table>
          <p class="hint">Only the auctioneer can decrypt these; they never appear on-chain. (This demo server holds the auctioneer's key and shows its view to anyone, for the demo.) The auctioneer is trusted for confidentiality, not for the outcome.</p>
        {:else}<p class="hint">No bids yet.</p>{/if}
      </div>
    </div>
    {#if state.history.length > 0}
      <h3>Transactions</h3>
      <table>
        <tbody>
          {#each state.history as h}<tr><td>{h.summary}</td><td>{h.cost ?? ''}</td><td><code>{h.txHash.substring(0, 20)}…</code></td></tr>{/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>
