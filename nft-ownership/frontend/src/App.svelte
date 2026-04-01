<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let loading = $state(false);
  let result = $state<any>(null);

  // Form inputs
  let secretKey = $state('42');
  let tokenName = $state('100');
  let contextId = $state('nft-demo-v1');

  async function loadStatus() {
    status = await api.status();
  }

  // Load status on mount
  $effect(() => { loadStatus(); });

  async function registerHolder() {
    loading = true;
    result = await api.registerHolder(secretKey, tokenName);
    loading = false;
  }

  async function buildSnapshot() {
    loading = true;
    result = await api.buildSnapshot();
    await loadStatus();
    loading = false;
  }

  async function generateProof() {
    loading = true;
    result = await api.generateProof(secretKey, tokenName, contextId);
    loading = false;
  }

  async function requestAccess() {
    if (!result?.nullifier) { alert('Generate a proof first!'); return; }
    loading = true;
    result = await api.requestAccess(result.nullifier);
    await loadStatus();
    loading = false;
  }
</script>

<main>
  <header>
    <h1>🔐 ZeroJ — Private NFT Ownership</h1>
    <p>Prove you own an NFT without revealing your wallet address</p>
    <nav>
      <button class:active={currentPage === 'home'} onclick={() => currentPage = 'home'}>Home</button>
      <button class:active={currentPage === 'register'} onclick={() => currentPage = 'register'}>Register</button>
      <button class:active={currentPage === 'prove'} onclick={() => currentPage = 'prove'}>Prove</button>
      <button class:active={currentPage === 'access'} onclick={() => currentPage = 'access'}>Access</button>
    </nav>
  </header>

  {#if currentPage === 'home'}
    <section>
      <h2>System Status</h2>
      {#if status}
        <div class="status-grid">
          <div class="card">
            <h3>Circuit</h3>
            <p>Tree Depth: {status.circuit?.treeDepth}</p>
            <p>Status: {status.circuit?.status}</p>
          </div>
          <div class="card">
            <h3>Snapshot</h3>
            <p>Holders: {status.snapshot?.holderCount}</p>
            <p>Epoch: {status.snapshot?.epoch}</p>
            <p class="mono">Root: {status.snapshot?.root?.substring(0, 16)}...</p>
          </div>
          <div class="card">
            <h3>Access</h3>
            <p>Used Nullifiers: {status.nullifiers?.usedCount}</p>
          </div>
        </div>
      {:else}
        <p>Loading...</p>
      {/if}
    </section>

  {:else if currentPage === 'register'}
    <section>
      <h2>Step 1: Register NFT Holders</h2>
      <p>Register NFT holders into the ownership Merkle tree, then build a snapshot.</p>

      <div class="form">
        <label>Secret Key (identifies wallet — never revealed)
          <input type="text" bind:value={secretKey} placeholder="42" />
        </label>
        <label>Token Name (NFT asset name as number)
          <input type="text" bind:value={tokenName} placeholder="100" />
        </label>
        <div class="buttons">
          <button onclick={registerHolder} disabled={loading}>
            {loading ? 'Registering...' : 'Register Holder'}
          </button>
          <button onclick={buildSnapshot} disabled={loading} class="secondary">
            {loading ? 'Building...' : 'Build Snapshot'}
          </button>
        </div>
      </div>

      {#if result}
        <div class="result">
          <h3>Result</h3>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      {/if}
    </section>

  {:else if currentPage === 'prove'}
    <section>
      <h2>Step 2: Generate ZK Proof</h2>
      <p>Prove you own an NFT without revealing your wallet address or which NFT.</p>

      <div class="form">
        <label>Secret Key (same as registration)
          <input type="text" bind:value={secretKey} />
        </label>
        <label>Token Name (same as registration)
          <input type="text" bind:value={tokenName} />
        </label>
        <label>Context ID (event/airdrop/vote identifier)
          <input type="text" bind:value={contextId} />
        </label>
        <button onclick={generateProof} disabled={loading}>
          {loading ? 'Generating proof...' : '🔑 Generate ZK Proof'}
        </button>
      </div>

      {#if result?.proof}
        <div class="result success">
          <h3>✅ Proof Generated!</h3>
          <p>Proving time: <strong>{result.provingTimeMs}ms</strong></p>
          <p>Nullifier: <code>{result.nullifier?.substring(0, 16)}...</code></p>
          <p class="note">This 192-byte proof reveals NOTHING about your wallet or which NFT you own.</p>
        </div>
      {:else if result?.error}
        <div class="result error">
          <h3>❌ Error</h3>
          <p>{result.error}</p>
        </div>
      {/if}
    </section>

  {:else if currentPage === 'access'}
    <section>
      <h2>Step 3: Access Gated Content</h2>
      <p>Present your ZK proof to gain anonymous access. The nullifier prevents double-use.</p>

      {#if result?.nullifier}
        <div class="form">
          <p>Nullifier from proof: <code>{result.nullifier?.substring(0, 16)}...</code></p>
          <button onclick={requestAccess} disabled={loading}>
            {loading ? 'Requesting...' : '🚪 Request Access'}
          </button>
        </div>
      {:else}
        <p>Generate a proof first (go to Prove tab).</p>
      {/if}

      {#if result?.access === true}
        <div class="result success">
          <h3>🎉 Access Granted!</h3>
          <p>{result.message}</p>
          <p>Total accesses: {result.totalAccesses}</p>
        </div>
      {:else if result?.access === false}
        <div class="result error">
          <h3>🚫 Access Denied</h3>
          <p>{result.reason}</p>
        </div>
      {/if}
    </section>
  {/if}
</main>

<style>
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    background: #0d1117;
    color: #c9d1d9;
  }

  header {
    text-align: center;
    margin-bottom: 2rem;
    border-bottom: 1px solid #30363d;
    padding-bottom: 1rem;
  }

  h1 { color: #58a6ff; margin-bottom: 0.5rem; }
  h2 { color: #58a6ff; }
  h3 { color: #c9d1d9; margin-top: 0; }

  nav {
    display: flex;
    gap: 8px;
    justify-content: center;
    margin-top: 1rem;
  }

  nav button {
    padding: 8px 16px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #c9d1d9;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
  }

  nav button:hover { background: #21262d; }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }

  .status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem;
  }

  .form {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.5rem;
    margin: 1rem 0;
  }

  label {
    display: block;
    margin-bottom: 1rem;
    font-size: 14px;
    color: #8b949e;
  }

  input {
    display: block;
    width: 100%;
    padding: 8px 12px;
    margin-top: 4px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 14px;
    font-family: monospace;
    box-sizing: border-box;
  }

  button {
    padding: 10px 20px;
    background: #238636;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
  }

  button:hover:not(:disabled) { background: #2ea043; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.secondary { background: #30363d; }
  button.secondary:hover:not(:disabled) { background: #484f58; }

  .buttons { display: flex; gap: 8px; margin-top: 1rem; }

  .result {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem;
    margin-top: 1rem;
  }

  .result.success { border-color: #238636; }
  .result.error { border-color: #da3633; }

  pre {
    background: #0d1117;
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 12px;
    color: #8b949e;
  }

  code { background: #0d1117; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  .mono { font-family: monospace; font-size: 13px; }
  .note { font-size: 13px; color: #8b949e; font-style: italic; }
</style>
