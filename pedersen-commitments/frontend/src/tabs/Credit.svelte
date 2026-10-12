<script lang="ts">
  import { get, post } from '../lib/api';
  import Outcome from '../lib/Outcome.svelte';

  let state = $state<any>(null);
  let busy = $state('');
  let result = $state<any>(null);

  let income = $state(85000);
  let creditScore = $state(720);
  let birthYear = $state(1990);
  let country = $state(356);
  let minIncome = $state(50000);
  let minScore = $state(650);

  async function load() {
    const r = await get('/credit');
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
  <h2>B. Committed credential</h2>
  <p class="hint">A credit bureau commits to four attributes of Alice's profile in <em>one</em> vector commitment
    (schema <code>{state?.schema?.id} v{state?.schema?.version}</code>) and records the issuance on-chain. Alice then
    proves <code>income ≥ X ∧ credit_score ≥ Y</code> to a lender's gate and receives a badge. The lender learns that
    she qualifies — not her income, score, birth year or country. Circuit: {state?.constraints ?? '…'} constraints.</p>

  <div class="actions">
    <div class="action">
      <h4>1. Bureau issues Alice's profile</h4>
      <label>income <input type="number" min="0" bind:value={income} /></label>
      <label>credit score <input type="number" min="0" max="65535" bind:value={creditScore} /></label>
      <label>birth year <input type="number" min="0" max="65535" bind:value={birthYear} /></label>
      <label>country (numeric code) <input type="number" min="0" max="65535" bind:value={country} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Committing and recording the issuance', '/credit/issue', { income, creditScore, birthYear, country })}>Issue and record</button>
    </div>
    <div class="action">
      <h4>2. Alice claims a badge from the lender</h4>
      <label>lender's minimum income <input type="number" min="0" bind:value={minIncome} /></label>
      <label>lender's minimum credit score <input type="number" min="0" max="65535" bind:value={minScore} /></label>
      <button class="primary" disabled={!!busy || !state?.private} onclick={() => act("Proving Alice's predicate and claiming", '/credit/claim', { who: 'alice', minIncome, minScore })}>Alice claims</button>
      <p class="hint">Raise a threshold above her profile to see that no proof exists.</p>
    </div>
    <div class="action cheat">
      <h4>Try to cheat: Mallory presents Alice's credential</h4>
      <p class="hint">Suppose Alice's opening leaked: Mallory has a valid proof for Alice's commitment. The issuance
        record names Alice, and the gate requires the named holder's signature.</p>
      <button class="danger" disabled={!!busy || !state?.private} onclick={() => act("Submitting Mallory's claim", '/credit/claim', { who: 'mallory', minIncome, minScore })}>Mallory claims</button>
    </div>
  </div>

  {#if busy}<p class="busy">{busy}… (proving and waiting for the block)</p>{/if}
  <Outcome {result} />

  {#if state}
    <div class="columns">
      <div class="panel private">
        <h3>Private — Alice's opening</h3>
        {#if state.private}
          <table>
            <tbody>
              <tr><td>income</td><td>{state.private.income}</td></tr>
              <tr><td>credit score</td><td>{state.private.creditScore}</td></tr>
              <tr><td>birth year</td><td>{state.private.birthYear}</td></tr>
              <tr><td>country</td><td>{state.private.country}</td></tr>
              <tr><td>blinding</td><td><code>{state.private.blinding}</code></td></tr>
            </tbody>
          </table>
        {:else}<p class="hint">No profile issued yet.</p>{/if}
      </div>
      <div class="panel public">
        <h3>On-chain — the issuance record</h3>
        {#if state.onChain}
          <table>
            <tbody>
              <tr><td>commitment u</td><td><code>{state.onChain.u}</code></td></tr>
              <tr><td>commitment v</td><td><code>{state.onChain.v}</code></td></tr>
              <tr><td>schema digest σ</td><td><code>{state.schema.digest}</code></td></tr>
              <tr><td>holder</td><td><code>{state.onChain.holder}</code></td></tr>
              <tr><td>record token</td><td><code>{state.onChain.recordToken}</code></td></tr>
              <tr><td>record tx</td><td><code>{state.onChain.recordTx.substring(0, 20)}…</code></td></tr>
            </tbody>
          </table>
        {:else}<p class="hint">Nothing recorded yet.</p>{/if}
        <h3>What the lender learns</h3>
        {#if state.claims.length === 0}<p class="hint">No badge claimed yet.</p>{/if}
        <table>
          <tbody>
            {#each state.claims as c}<tr><td>{c.claimant}: {c.lenderLearns}</td><td><code>{c.txHash.substring(0, 16)}…</code></td></tr>{/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
</section>
