<script lang="ts">
  import { get, post } from '../lib/api';
  import Outcome from '../lib/Outcome.svelte';
  import NoteLedgerView from '../lib/NoteLedgerView.svelte';

  let state = $state<any>(null);
  let busy = $state('');
  let result = $state<any>(null);

  let payTo = $state('carol');
  let salary = $state(5000);
  let reported = $state(3000);
  let from = $state('carol');
  let to = $state('dave');
  let amount = $state(800);
  let cashOutFrom = $state('carol');
  let cashOut = $state(1000);

  const employees = ['carol', 'dave'];

  async function load() {
    const r = await get('/payroll');
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
  <h2>Confidential payroll</h2>
  <p class="hint">The employer pays salaries as confidential notes. Unlike the points demo, <strong>issuance is
    proof-enforced</strong> (ADR-0055 Q9 (b)): every pay run carries a Groth16 proof that each salary note's limbs encrypt
    its committed amount to the tax authority's registered key. So the tax authority reads every salary from the chain,
    and the employer cannot under-report one. Employees read their payslips from the chain with their viewing keys.
    Circuits: pay {state?.constraints?.issue ?? '…'} constraints, transfer {state?.constraints?.transfer ?? '…'},
    cash-out {state?.constraints?.redeem ?? '…'}.</p>

  <div class="actions">
    <div class="action">
      <h4>Pay a salary (employer)</h4>
      <label>to <select bind:value={payTo}>{#each employees as e}<option>{e}</option>{/each}</select></label>
      <label>salary <input type="number" min="1" bind:value={salary} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Proving and submitting the pay run', '/payroll/pay', { to: payTo, amount: salary })}>Pay</button>
    </div>
    <div class="action">
      <h4>Transfer between employees</h4>
      <label>from <select bind:value={from}>{#each employees as e}<option>{e}</option>{/each}</select></label>
      <label>to <select bind:value={to}>{#each employees as e}<option>{e}</option>{/each}</select></label>
      <label>amount <input type="number" min="1" bind:value={amount} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Proving and submitting the transfer', '/payroll/transfer', { from, to, amount })}>Transfer</button>
    </div>
    <div class="action">
      <h4>Cash out at the employer</h4>
      <label>from <select bind:value={cashOutFrom}>{#each employees as e}<option>{e}</option>{/each}</select></label>
      <label>amount (public) <input type="number" min="1" bind:value={cashOut} /></label>
      <button class="primary" disabled={!!busy} onclick={() => act('Proving and submitting the cash-out', '/payroll/cash-out', { from: cashOutFrom, amount: cashOut })}>Cash out</button>
    </div>
    <div class="action">
      <h4>Tax authority key rotation</h4>
      <p class="hint">Registry generation {state?.registry?.generation ?? '…'}.</p>
      <button disabled={!!busy} onclick={() => act('Rotating the tax authority keys', '/payroll/rotate', {})}>Rotate keys</button>
    </div>
  </div>

  <h3>Try to cheat</h3>
  <div class="actions">
    <div class="action cheat">
      <h4>Under-report a salary to the tax authority</h4>
      <label>tell the tax authority <input type="number" min="0" bind:value={reported} /></label>
      <p class="hint">The employer pays {salary} but encrypts {reported} to the tax authority. The issuance proof cannot be
        produced — compare the points tab, where trusted issuance lets the issuer do this.</p>
      <button class="danger" disabled={!!busy} onclick={() => act('Proving an under-reported pay run', '/payroll/pay', { to: payTo, amount: salary, reported })}>Pay and under-report</button>
    </div>
    <div class="action cheat">
      <h4>Garbage payslip</h4>
      <p class="hint">{from} sends {amount} to {to} with a garbage encrypted opening: {to} sees an unopenable payslip, while
        the tax authority still reads the amount.</p>
      <button class="danger" disabled={!!busy} onclick={() => act('Submitting a garbage payslip', '/payroll/transfer', { from, to, amount, cheat: 'garbageDelivery' })}>Send a garbage payslip</button>
    </div>
    <div class="action cheat">
      <h4>Limbs to the retired key</h4>
      <p class="hint">After a rotation, the amounts are encrypted to the tax authority's previous key: refused.</p>
      <button class="danger" disabled={!!busy || !state?.canUseRetiredKey} onclick={() => act('Submitting a transfer to the retired key', '/payroll/transfer', { from, to, amount, cheat: 'retiredKey' })}>Use the retired key</button>
    </div>
  </div>

  {#if busy}<p class="busy">{busy}… (proving and waiting for the block)</p>{/if}
  <Outcome {result} />

  {#if state}
    {#if state.auditor.payslips}
      <div class="panel auditor">
        <h3>Tax authority — every salary ever paid (from the chain's mint history)</h3>
        <p class="hint">Each pay run's notes, including ones already transferred or cashed out, read from the limb ciphertexts.
          Every one is proof-enforced: the employer could not have under-reported it.</p>
        <table>
          <thead><tr><th>payslip UTxO</th><th>employee</th><th>salary</th><th>origin</th><th>check</th></tr></thead>
          <tbody>
            {#each state.auditor.payslips as p}<tr><td><code>{p.utxo}</code></td><td>{p.owner}</td><td><strong>{p.amount}</strong></td><td>{p.origin}</td><td>{p.status}</td></tr>{/each}
          </tbody>
        </table>
        <p class="hint">Salary totals:
          {#each Object.entries(state.auditor.paidTotals) as [who, total], i}{i > 0 ? ' · ' : ''}{who} {total}{/each}</p>
      </div>
    {/if}
    <NoteLedgerView {state} unit="credits" />
  {/if}
</section>
