<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let pageData = $state<any>(null);
  let loading = $state(false);
  let message = $state('');
  let reservesInput = $state(10000);
  let verifyAccountId = $state('alice');
  let verifyResult = $state<any>(null);
  let proveResult = $state<any>(null);
  let disableOffchain = $state(false);
  let page = $state(0);

  async function loadStatus() { status = await api.status(); loadPage(0); }
  async function loadPage(p: number) { page = Math.max(0, p); pageData = await api.listAccounts(page, 20); }
  $effect(() => { loadStatus(); });

  async function addAccounts(count: number) {
    loading = true; message = `Adding ${count} accounts...`;
    await api.addAccounts(count);
    message = `Added ${count} accounts.`; loadStatus(); loading = false;
  }

  async function buildTree() {
    loading = true; message = 'Building Merkle Sum Tree...';
    const r = await api.buildTree();
    message = `Tree built: ${r.accountCount} accounts, total liabilities: ${r.totalLiabilitiesAda} ADA`;
    loadStatus(); loading = false;
  }

  async function proveSolvency() {
    loading = true; proveResult = null;
    message = `Step 1: Building tree + generating ZK solvency proof (reserves=${reservesInput} ADA)...`;
    try {
      await api.buildTree();
      message = `Step 2: Submitting proof to Cardano for on-chain Groth16 verification...`;
      proveResult = await api.prove(reservesInput, disableOffchain);
      if (proveResult.error) {
        let detail = proveResult.onChainRejection ? ' — REJECTED BY ON-CHAIN PLUTUS VALIDATOR' : '';
        message = `❌ ${proveResult.error.substring(0, 100)}${detail}`;
      } else if (proveResult.solvent) {
        message = `✅ SOLVENT! Groth16 proof verified ON-CHAIN. tx: ${proveResult.txHash?.substring(0, 20)}... (${proveResult.provingTimeMs}ms)`;
      } else {
        message = `❌ INSOLVENT — reserves (${reservesInput}) < liabilities (${proveResult.liabilitiesAda}). ${proveResult.message}`;
      }
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function verifyAccount() {
    loading = true; verifyResult = null;
    verifyResult = await api.verifyAccount(verifyAccountId);
    message = verifyResult.message || verifyResult.error || '';
    loading = false;
  }
</script>

<main>
  <h1>Proof of Reserves Demo</h1>
  <p class="subtitle">Prove solvency without revealing individual balances — Merkle Sum Tree + Groth16 on Cardano</p>

  <nav>
    <button class:active={currentPage === 'home'} onclick={() => { currentPage = 'home'; loadStatus(); }}>Accounts</button>
    <button class:active={currentPage === 'exchange'} onclick={() => { currentPage = 'exchange'; loadStatus(); }}>Exchange (Prove)</button>
    <button class:active={currentPage === 'user'} onclick={() => currentPage = 'user'}>User (Verify)</button>
  </nav>

  {#if currentPage === 'home'}
    <section>
      <h2>Account Registry</h2>
      {#if status}
        <p>Accounts: {status.accountCount} | Total liabilities: {status.totalLiabilitiesAda} ADA | Tree: {status.treeBuilt ? '✓ built' : 'not built'} | Max: {status.maxAccounts}</p>
      {/if}
      <div class="action-bar">
        <button onclick={() => addAccounts(5)} disabled={loading}>Add 5 random</button>
        <button onclick={buildTree} disabled={loading}>Build Merkle Sum Tree</button>
      </div>
      {#if pageData}
        <table>
          <thead><tr><th>Account ID</th><th>Name</th><th>Balance (ADA)</th></tr></thead>
          <tbody>
            {#each pageData.accounts as a}
              <tr><td><code>{a.accountId}</code></td><td>{a.name}</td><td class="num">{a.balanceAda.toFixed(1)}</td></tr>
            {/each}
          </tbody>
        </table>
        <div class="pagination">
          <button onclick={() => loadPage(page - 1)} disabled={page <= 0}>Prev</button>
          <span>Page {pageData.page + 1} of {Math.max(1, pageData.totalPages)} ({pageData.totalElements} total)</span>
          <button onclick={() => loadPage(page + 1)} disabled={page >= pageData.totalPages - 1}>Next</button>
        </div>
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
    </section>

  {:else if currentPage === 'exchange'}
    <section>
      <h2>Exchange — Prove Solvency</h2>
      <div class="note">
        <strong>How it works:</strong>
        <ol>
          <li><strong>Off-chain:</strong> Build Merkle Sum Tree from all accounts, generate Groth16 BLS12-381 proof (~5-15s)</li>
          <li><strong>On-chain:</strong> Plutus V3 validator verifies: Groth16 pairing check + isSolvent=1</li>
        </ol>
        <p>The proof proves: reserves &gt;= total liabilities, all balances &gt;= 0, and the sum tree root is correct — without revealing any individual balance.</p>
      </div>

      <div class="prove-form">
        <label>Declared reserves (ADA):</label>
        <input type="number" bind:value={reservesInput} min="0" step="100" />
        {#if status}
          <span class="hint">Liabilities: {status.totalLiabilitiesAda} ADA</span>
        {/if}
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={disableOffchain} />
          <strong>Skip off-chain check</strong> — send insolvent proofs to chain (Plutus will reject)
        </label>
        <button class="btn-prove" onclick={proveSolvency} disabled={loading}>
          {loading ? 'Proving...' : 'Prove Solvency (On-Chain)'}
        </button>
      </div>

      {#if proveResult && !proveResult.error}
        <div class="result" class:solvent={proveResult.solvent} class:insolvent={!proveResult.solvent}>
          <h3>{proveResult.solvent ? '✅ SOLVENT' : '❌ INSOLVENT'}</h3>
          <p>Reserves: {proveResult.reservesAda} ADA | Liabilities: {proveResult.liabilitiesAda} ADA</p>
          {#if proveResult.txHash}<p>On-chain tx: <code>{proveResult.txHash}</code></p>{/if}
          {#if proveResult.provingTimeMs}<p>Proof time: {proveResult.provingTimeMs}ms</p>{/if}
        </div>
      {/if}
      {#if proveResult?.onChainValidation}
        <div class="onchain-error">
          <h3>{proveResult.onChainValidation.title}</h3>
          <p>{proveResult.onChainValidation.summary}</p>
          <pre>{proveResult.onChainValidation.detail}</pre>
        </div>
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
    </section>

  {:else if currentPage === 'user'}
    <section>
      <h2>User — Verify Your Balance</h2>
      <p>Enter your account ID to verify your balance is correctly included in the exchange's solvency proof.</p>
      <div class="verify-form">
        <input type="text" bind:value={verifyAccountId} placeholder="Account ID (e.g., alice)" />
        <button onclick={verifyAccount} disabled={loading}>Verify Inclusion</button>
      </div>
      {#if verifyResult}
        <div class="result" class:solvent={verifyResult.included && verifyResult.rootMatches} class:insolvent={!verifyResult.included || !verifyResult.rootMatches}>
          {#if verifyResult.included}
            <h3>{verifyResult.rootMatches ? '✅ Verified' : '❌ Root Mismatch!'}</h3>
            <p>Account: {verifyResult.name} | Balance: {verifyResult.balanceAda} ADA | Leaf index: {verifyResult.leafIndex}</p>
          {:else}
            <h3>❌ Not Included</h3>
          {/if}
          <p>{verifyResult.message}</p>
        </div>
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
    </section>
  {/if}
</main>

<style>
  :global(body) { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 950px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; margin-bottom: 4px; } .subtitle { color: #8b949e; margin-top: 0; }
  nav { display: flex; gap: 8px; margin: 20px 0; }
  nav button { padding: 8px 18px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }
  .action-bar { display: flex; gap: 8px; margin: 12px 0; }
  .action-bar button { padding: 6px 16px; border: none; border-radius: 6px; background: #238636; color: white; cursor: pointer; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.9em; }
  th { color: #8b949e; } code { font-size: 0.83em; color: #79c0ff; } .num { text-align: right; font-variant-numeric: tabular-nums; }
  .pagination { display: flex; gap: 12px; align-items: center; justify-content: center; margin: 12px 0; }
  .pagination button { padding: 6px 14px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  .pagination button:disabled { opacity: 0.4; } .pagination span { color: #8b949e; font-size: 0.9em; }
  .note { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #1f6feb; border-radius: 6px; padding: 12px 16px; margin: 12px 0; font-size: 0.88em; }
  .note ol { margin: 6px 0; padding-left: 20px; } .note li { margin: 4px 0; } .note p { margin: 6px 0 0; color: #8b949e; }
  .prove-form { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 16px 0; display: flex; flex-direction: column; gap: 10px; }
  .prove-form input[type="number"] { padding: 8px; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; border-radius: 6px; width: 200px; font-size: 1.1em; }
  .prove-form .hint { color: #8b949e; font-size: 0.85em; }
  .btn-prove { padding: 10px 24px; border: none; border-radius: 6px; background: #1f6feb; color: white; font-weight: bold; cursor: pointer; font-size: 1em; }
  .btn-prove:disabled { opacity: 0.5; }
  .checkbox-label { display: flex; align-items: flex-start; gap: 8px; padding: 8px 12px; background: #1c1208; border: 1px solid #d29922; border-radius: 6px; font-size: 0.85em; cursor: pointer; }
  .verify-form { display: flex; gap: 8px; margin: 16px 0; }
  .verify-form input { padding: 8px 12px; border: 1px solid #30363d; background: #161b22; color: #c9d1d9; border-radius: 6px; flex: 1; }
  .verify-form button { padding: 8px 20px; border: none; border-radius: 6px; background: #238636; color: white; cursor: pointer; font-weight: bold; }
  .result { border-radius: 8px; padding: 16px; margin: 16px 0; }
  .solvent { background: #0d2818; border: 1px solid #238636; }
  .insolvent { background: #2d1214; border: 1px solid #da3633; }
  .onchain-error { background: #2d1214; border: 1px solid #da3633; border-radius: 8px; padding: 16px; margin: 16px 0; }
  .onchain-error h3 { color: #f85149; margin: 0 0 8px; }
  .onchain-error p { margin: 0 0 12px; }
  .onchain-error pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #ffb4ad; padding: 12px; max-height: 260px; overflow-y: auto; }
  .message { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin: 12px 0; color: #58a6ff; }
  button { cursor: pointer; } button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
