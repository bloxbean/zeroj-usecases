<script lang="ts">
  import { get } from './lib/api';
  import Points from './tabs/Points.svelte';
  import Credit from './tabs/Credit.svelte';
  import Solvency from './tabs/Solvency.svelte';
  import Payroll from './tabs/Payroll.svelte';
  import Auction from './tabs/Auction.svelte';

  let tab = $state('points');
  let status = $state<any>(null);

  async function poll() {
    const r = await get('/status');
    status = r.data;
    if (!status?.ready) setTimeout(poll, 3000);
  }

  $effect(() => { poll(); });
</script>

<main>
  <h1>Pedersen Commitments on Cardano</h1>
  <p class="subtitle">Hiding, binding and additive commitments with zero-knowledge proofs, verified by Plutus V3 on Yaci DevKit</p>

  <div class="notice">
    <strong>Demo server.</strong> This server creates every wallet and holds every key on the users' behalf — spending
    keys, note viewing keys, the auditor's keys — and scans the chain for them; real users would each keep their own and
    scan in their own wallet (ZeroJ ADR-0055 D9). Note balances are recovered from the chain, not kept in memory.
    The <em>On-chain</em> panels show what anyone can read from the ledger.
  </div>

  {#if !status?.ready}
    <div class="card">
      <p><strong>Starting…</strong> compiling circuits, loading or generating development keys and funding demo wallets.
        Each tab opens as soon as its demo is ready. Cached keys are re-validated point by point on every start (about
        two minutes); the very first start also generates them, which takes longer.</p>
      {#if status?.demos}
        <p>
          {#each Object.entries(status.demos) as [name, s]}
            <span class="pill" class:ready={s === 'ready'}>{name}: {s}</span>
          {/each}
        </p>
      {/if}
    </div>
  {/if}

  <nav>
    <button class:active={tab === 'points'} onclick={() => (tab = 'points')}>A. Confidential points</button>
    <button class:active={tab === 'payroll'} onclick={() => (tab = 'payroll')}>Confidential payroll</button>
    <button class:active={tab === 'auction'} onclick={() => (tab = 'auction')}>Sealed-bid auction</button>
    <button class:active={tab === 'credit'} onclick={() => (tab = 'credit')}>B. Committed credential</button>
    <button class:active={tab === 'solvency'} onclick={() => (tab = 'solvency')}>C. Hidden-liability solvency</button>
  </nav>

  {#if status?.demos?.[tab] === 'ready'}
    {#if tab === 'points'}<Points />{/if}
    {#if tab === 'payroll'}<Payroll />{/if}
    {#if tab === 'auction'}<Auction />{/if}
    {#if tab === 'credit'}<Credit />{/if}
    {#if tab === 'solvency'}<Solvency />{/if}
  {:else if status}
    <p class="hint">This demo is {status?.demos?.[tab] ?? 'starting'}…</p>
  {/if}
</main>

<style>
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    max-width: 1180px;
    margin: 0 auto;
    padding: 20px;
    background: #0d1117;
    color: #c9d1d9;
  }
  :global(h2) { color: #c9d1d9; margin: 8px 0; }
  :global(h3) { color: #58a6ff; margin: 12px 0 6px; font-size: 1em; }
  :global(.card) { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; margin: 12px 0; }
  :global(.columns) { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  :global(.panel) { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 14px; }
  :global(.panel.private) { border-color: #8957e5; }
  :global(.panel.private h3) { color: #d2a8ff; }
  :global(.panel.public) { border-color: #1f6feb; }
  :global(table) { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 0.9em; }
  :global(th), :global(td) { padding: 5px 8px; text-align: left; border-bottom: 1px solid #21262d; }
  :global(th) { color: #8b949e; font-weight: normal; }
  :global(code) { font-size: 0.85em; color: #79c0ff; }
  :global(.hint) { color: #8b949e; font-size: 0.9em; }
  :global(.actions) { display: flex; flex-wrap: wrap; gap: 12px; }
  :global(.action) { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 10px 12px; flex: 1 1 250px; }
  :global(.action h4) { margin: 0 0 8px; color: #c9d1d9; }
  :global(.action.cheat) { border-color: #da3633; }
  :global(.action.cheat h4) { color: #f85149; }
  :global(label) { display: block; font-size: 0.85em; color: #8b949e; margin: 4px 0; }
  :global(input), :global(select) { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 5px 7px; width: 100%; box-sizing: border-box; }
  :global(button.primary), :global(button.danger) { margin-top: 8px; padding: 7px 14px; border: none; border-radius: 6px; color: white; font-weight: bold; cursor: pointer; }
  :global(button.primary) { background: #238636; }
  :global(button.danger) { background: #da3633; }
  :global(button:disabled) { opacity: 0.5; cursor: not-allowed; }
  :global(.busy) { color: #58a6ff; margin: 8px 0; }
  h1 { color: #58a6ff; margin-bottom: 4px; }
  .subtitle { color: #8b949e; margin-top: 0; }
  .notice { background: #1c1f26; border: 1px solid #d29922; border-radius: 8px; padding: 10px 14px; color: #e3b341; font-size: 0.92em; }
  nav { display: flex; gap: 8px; margin: 18px 0 8px; flex-wrap: wrap; }
  nav button { padding: 8px 18px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }
  .pill { display: inline-block; padding: 2px 10px; margin: 2px; border-radius: 12px; background: #30363d; font-size: 0.85em; }
  .pill.ready { background: #238636; color: white; }
</style>
