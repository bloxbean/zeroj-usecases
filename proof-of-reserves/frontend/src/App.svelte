<script lang="ts">
  import { api } from './lib/api';
  import { check, Outcome } from './lib/reserves/customerCheck.js';
  import { yaciStoreIndexer } from './lib/reserves/indexer.js';

  // The attestation policy and clock the customer trusts. Pinned in this browser on first use; a
  // real customer takes them from a published source, not from the custodian's API.
  const PIN_KEY = 'zeroj.reserves.pinnedDeployment.v1';
  function loadPinned(): any {
    try { const v = localStorage.getItem(PIN_KEY); return v ? JSON.parse(v) : null; } catch { return null; }
  }
  function savePinned(v: any) {
    try { localStorage.setItem(PIN_KEY, JSON.stringify(v)); } catch { /* storage unavailable: kept for this page only */ }
  }
  let pinned = $state<any>(loadPinned());
  // The indexer is not pinned from the server: it defaults to the configured value and the
  // customer can point the check at any indexer they trust.
  const INDEXER_KEY = 'zeroj.reserves.indexerUrl.v1';
  function loadIndexer(): string {
    try { return localStorage.getItem(INDEXER_KEY) ?? ''; } catch { return ''; }
  }
  function saveIndexer() {
    try {
      if (indexerOverride.trim()) localStorage.setItem(INDEXER_KEY, indexerOverride.trim());
      else localStorage.removeItem(INDEXER_KEY);
    } catch { /* storage unavailable */ }
  }
  let indexerOverride = $state<string>(loadIndexer());
  let served = $state<any>(null);
  let checking = $state(false);
  const pinFields = ['policyId', 'genesisMs', 'periodMs'];
  let indexerUrl = $derived(indexerOverride.trim() || served?.indexerUrl || 'http://localhost:8080/api/v1/');
  let pinMismatch = $derived(!!(served && pinned && pinFields.some((k) => String(served[k]) !== String(pinned[k]))));

  async function loadDeployment() {
    try {
      served = await api.deployment();
      if (!pinned && served?.policyId) { pin(served); }
    } catch { served = null; }
  }
  function pin(d: any) {
    pinned = { policyId: d.policyId, genesisMs: String(d.genesisMs), periodMs: String(d.periodMs) };
    savePinned(pinned);
  }
  const outcomeText: Record<string, string> = {
    [Outcome.VERIFIED]: 'Verified against the chain',
    [Outcome.ROOT_MISMATCH]: 'Not included: the attested root differs',
    [Outcome.NO_ATTESTATION]: 'No attestation for the current period',
    [Outcome.DUPLICATE_ATTESTATION]: 'Refused: this period was attested more than once',
    [Outcome.HISTORY_INCOMPLETE]: 'Refused: mint history unavailable or incomplete',
    [Outcome.INDEXER_UNAVAILABLE]: 'Refused: chain indexer unavailable',
    [Outcome.NOT_AT_SCRIPT_ADDRESS]: 'Refused: token not at the attestation address',
    [Outcome.BAD_DATUM]: 'Refused: malformed attestation datum',
    [Outcome.WRONG_PERIOD]: 'Refused: attestation is for another period',
    [Outcome.BEFORE_GENESIS]: 'No period has started yet',
    [Outcome.BAD_INPUT]: 'Refused: malformed inclusion data',
  };

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

  async function loadStatus() { status = await api.status(); loadPage(0); loadDeployment(); }
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

  // The customer's check (ADR-0009 D4.3): inclusion data from the custodian, everything else
  // recomputed here and read from the chain indexer.
  async function verifyAccount() {
    loading = true; checking = true; verifyResult = null; message = '';
    try {
      const data = await api.verifyAccount(verifyAccountId);
      if (data.error || !data.included) {
        verifyResult = { data, check: null };
        message = data.error || data.message || '';
        return;
      }
      if (!pinned) { message = 'No pinned attestation policy: load it first.'; return; }
      const r = await check({ accountId: verifyAccountId, salt: data.salt, balance: data.balanceLovelace,
        leafIndex: data.leafIndex, siblings: data.siblings }, pinned, yaciStoreIndexer(indexerUrl));
      verifyResult = { data, check: r };
    } catch (e: any) {
      message = `Error: ${e.message}`;
    } finally {
      loading = false; checking = false;
    }
  }
</script>

<main>
  <h1>Proof of Reserves Demo</h1>
  <p class="subtitle">Prove solvency without revealing individual balances — salted Merkle tree + Groth16 on Cardano</p>

  <nav>
    <button class:active={currentPage === 'home'} onclick={() => { currentPage = 'home'; loadStatus(); }}>Accounts (operator view)</button>
    <button class:active={currentPage === 'exchange'} onclick={() => { currentPage = 'exchange'; loadStatus(); }}>Exchange (Prove)</button>
    <button class:active={currentPage === 'user'} onclick={() => { currentPage = 'user'; loadDeployment(); }}>Customer (Verify)</button>
  </nav>

  {#if currentPage === 'home'}
    <section>
      <h2>Account Registry</h2>
      <div class="note warn"><strong>Operator view.</strong> This list (and <code>/accounts</code>, <code>/verify</code>) is the demo custodian's own view of every balance. The server holds all data and answers anyone; privacy in this demo holds against chain observers, not against this server.</div>
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
          <li><strong>Off-chain:</strong> build a fresh salted Merkle tree from all accounts (new 252-bit salt per account), generate the Groth16 BLS12-381 proof (~5-15s)</li>
          <li><strong>On-chain:</strong> the custodian mints this period's attestation token into the attestation script address. The minting policy verifies the proof against <code>[totalReserves, root, totalLiabilities, 1]</code> read from the token's datum, so only a solvent statement mints.</li>
        </ol>
        <p>The proof shows: declared reserves &gt;= the sum of the balances, every balance is a 64-bit non-negative value, and the balances are the leaves of the published root — without revealing any individual balance.</p>
        <p><strong>Limits:</strong> <code>totalReserves</code> is declared by the custodian; nothing checks it against on-chain holdings. The proof checks the sum, not that the balances are true. One attestation per period is the custodian's word; customer pages refuse a period minted twice.</p>
      </div>

      <div class="prove-form">
        <label>Declared reserves (ADA):</label>
        <input type="number" bind:value={reservesInput} min="0" step="100" />
        {#if status}
          <span class="hint">Liabilities: {status.totalLiabilitiesAda} ADA</span>
        {/if}
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={disableOffchain} />
          <strong>Skip off-chain check</strong> — try to mint with an insolvent proof (the minting policy will reject)
        </label>
        <button class="btn-prove" onclick={proveSolvency} disabled={loading}>
          {loading ? 'Proving...' : 'Prove Solvency (On-Chain)'}
        </button>
      </div>

      {#if proveResult && !proveResult.error}
        <div class="result" class:solvent={proveResult.solvent} class:insolvent={!proveResult.solvent}>
          <h3>{proveResult.solvent ? '✅ SOLVENT' : '❌ INSOLVENT'}</h3>
          <p>Reserves: {proveResult.reservesAda} ADA | Liabilities: {proveResult.liabilitiesAda} ADA</p>
          {#if proveResult.txHash}<p>Attestation for period {proveResult.period}, tx: <code>{proveResult.txHash}</code></p>{/if}
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
      <h2>Customer — Check Your Balance Against the Chain</h2>
      <p>The custodian gives you your salt, balance, leaf index and sibling path. This page recomputes the root here in your browser, reads this period's attestation token from the chain indexer (not from the custodian), refuses a period minted more than once, and compares the roots.</p>

      <div class="note">
        <strong>Pinned attestation policy</strong> (stored in this browser; a real customer takes these from a published source)
        {#if pinned}
          <div class="pin-grid">
            <label>Policy id <input type="text" bind:value={pinned.policyId} onchange={() => savePinned(pinned)} /></label>
            <label>Genesis (POSIX ms) <input type="text" bind:value={pinned.genesisMs} onchange={() => savePinned(pinned)} /></label>
            <label>Period (ms) <input type="text" bind:value={pinned.periodMs} onchange={() => savePinned(pinned)} /></label>
          </div>
        {:else}
          <p>Not pinned yet.</p>
        {/if}
        <div class="pin-grid">
          <label>Chain indexer (Yaci Store), blank for the configured default <input type="text" bind:value={indexerOverride} placeholder={served?.indexerUrl ?? 'http://localhost:8080/api/v1/'} onchange={saveIndexer} /></label>
        </div>
        <p class="warn-text">This page and the values pinned on first use come from the custodian's own server. A real customer takes the policy id and clock from a published source and runs the check from code they trust.</p>
        {#if pinMismatch}
          <p class="warn-text">The custodian now reports a different policy or clock than the one you pinned. The check uses your pinned values.</p>
        {/if}
        <button class="small" onclick={() => served && pin(served)} disabled={!served}>Pin what the custodian reports</button>
      </div>

      <div class="verify-form">
        <input type="text" bind:value={verifyAccountId} placeholder="Account ID (e.g., alice)" />
        <button onclick={verifyAccount} disabled={loading || !pinned}>{checking ? 'Checking...' : 'Check inclusion'}</button>
      </div>
      {#if verifyResult}
        {#if verifyResult.check}
          {@const r = verifyResult.check}
          <div class="result" class:solvent={r.verified} class:insolvent={!r.verified}>
            <h3>{r.verified ? '✅' : '❌'} {outcomeText[r.outcome] ?? r.outcome}</h3>
            <p>{r.detail}</p>
            <ol class="steps">
              <li>From the custodian (operator view): balance <strong>{verifyResult.data.balanceAda} ADA</strong>, leaf {verifyResult.data.leafIndex}, {verifyResult.data.siblings.length} siblings. <em>Compare this balance with your own records.</em></li>
              <li>Recomputed root (in this browser): <code>{r.root?.toString(16).slice(0, 24)}…</code></li>
              {#if r.period !== undefined}<li>Current period from the chain: {r.period.toString()}</li>{/if}
              {#if r.attestation}
                <li>Attested root: <code>{r.attestation.liabilitiesRoot.toString(16).slice(0, 24)}…</code>, liabilities {Number(r.attestation.totalLiabilities) / 1e6} ADA, declared reserves {Number(r.attestation.totalReserves) / 1e6} ADA{#if r.txHash} (output <code>{r.txHash.slice(0, 16)}…</code>){/if}</li>
              {/if}
            </ol>
          </div>
        {:else}
          <div class="result insolvent">
            <h3>❌ Not included</h3>
            <p>{verifyResult.data.message || verifyResult.data.error}</p>
          </div>
        {/if}
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
  .note.warn { border-left-color: #d29922; }
  .warn-text { color: #d29922; }
  .pin-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 8px 0; }
  .pin-grid label { display: flex; flex-direction: column; gap: 4px; color: #8b949e; font-size: 0.85em; }
  .pin-grid input { padding: 6px 8px; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; border-radius: 6px; font-family: monospace; font-size: 0.85em; }
  button.small { padding: 4px 12px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; }
  .steps { margin: 8px 0 0; padding-left: 20px; font-size: 0.88em; } .steps li { margin: 4px 0; }
  @media (max-width: 640px) { .pin-grid { grid-template-columns: 1fr; } }
</style>
