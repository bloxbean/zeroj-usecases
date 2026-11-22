<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let mintStatus = $state<any>(null);
  let loading = $state(false);
  let result = $state<any>(null);
  let proofResult = $state<any>(null);

  // Form inputs. No default secret: the server draws a 252-bit secret at registration.
  let secretKey = $state('');
  let tokenName = $state('');

  async function loadStatus() {
    status = await api.status();
    mintStatus = await api.mintStatus();
    if (!tokenName && mintStatus?.mintedTokens?.length) tokenName = mintStatus.mintedTokens[0];
  }

  // Load status on mount
  $effect(() => { loadStatus(); });

  async function mintNfts() {
    loading = true;
    result = await api.mint('ZeroJTicket', 3);
    await loadStatus();
    loading = false;
  }

  async function registerHolder() {
    loading = true;
    result = await api.registerHolder(tokenName);
    if (result?.secretKey) secretKey = result.secretKey;
    await loadStatus();
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
    proofResult = await api.generateProof(secretKey, tokenName);
    result = proofResult;
    loading = false;
  }

  async function requestAccess() {
    if (!proofResult?.nullifier) { alert('Generate a proof first!'); return; }
    loading = true;
    result = await api.requestAccess(proofResult.nullifier);
    await loadStatus();
    loading = false;
  }
</script>

<main>
  <header>
    <h1>ZeroJ — Private NFT Ownership</h1>
    <p>Prove you hold an NFT of the collection without revealing which NFT or which wallet</p>
    <nav>
      <button class:active={currentPage === 'home'} onclick={() => currentPage = 'home'}>Home</button>
      <button class:active={currentPage === 'register'} onclick={() => currentPage = 'register'}>Register</button>
      <button class:active={currentPage === 'prove'} onclick={() => currentPage = 'prove'}>Prove</button>
      <button class:active={currentPage === 'access'} onclick={() => currentPage = 'access'}>Access</button>
    </nav>
  </header>

  <p class="operator-note">
    Demo operator view: this server holds the custody wallet with the NFTs, draws the holder
    secrets and proves for the holder. Privacy holds against chain and mempool observers, not
    against this server.
  </p>

  {#if currentPage === 'home'}
    <section>
      <h2>System Status</h2>
      {#if status}
        <div class="status-grid">
          <div class="card">
            <h3>Event</h3>
            <p>Context: <code>{status.event?.contextId}</code></p>
            <p>Circuit version: {status.event?.circuitVersion} (depth {status.circuit?.treeDepth})</p>
            {#if status.event?.zkPolicyId}
              <p class="mono">ZK policy: {status.event.zkPolicyId.substring(0, 16)}...</p>
            {/if}
          </div>
          <div class="card">
            <h3>Snapshot</h3>
            <p>Holders: {status.snapshot?.holderCount}</p>
            <p>Registration: {status.snapshot?.registrationOpen ? 'open' : 'closed (snapshot built)'}</p>
            <p class="mono">Root: {status.snapshot?.root?.substring(0, 16)}...</p>
          </div>
          <div class="card">
            <h3>Access</h3>
            <p>Used Nullifiers: {status.nullifiers?.usedCount}</p>
            <p>Mode: {status.nullifiers?.mode}</p>
          </div>
        </div>
      {:else}
        <p>Loading...</p>
      {/if}
    </section>

  {:else if currentPage === 'register'}
    <section>
      <h2>Step 1: Register NFT Holders</h2>
      <p>
        Mint the collection into the custody wallet, then register each NFT. The custody wallet
        signs every registration (CIP-8) and the snapshot checks it against the token's on-chain
        holder. One leaf per NFT. Building the snapshot closes registration for this event.
      </p>

      <div class="form">
        <div class="buttons">
          <button onclick={mintNfts} disabled={loading} class="secondary">
            {loading ? 'Working...' : 'Mint 3 NFTs into custody'}
          </button>
        </div>
        {#if mintStatus?.mintedTokens?.length}
          <label>NFT to register
            <select bind:value={tokenName}>
              {#each mintStatus.mintedTokens as t}
                <option value={t}>{t}</option>
              {/each}
            </select>
          </label>
        {/if}
        <div class="buttons">
          <button onclick={registerHolder} disabled={loading || !tokenName || status?.snapshot?.registrationOpen === false}>
            {loading ? 'Registering...' : 'Register holder (new 252-bit secret)'}
          </button>
          <button onclick={buildSnapshot} disabled={loading || status?.snapshot?.registrationOpen === false} class="secondary">
            {loading ? 'Building...' : 'Build snapshot and deploy event'}
          </button>
        </div>
      </div>

      {#if result?.secretKey}
        <div class="result">
          <h3>Holder secret for {result.tokenName}</h3>
          <p class="note">Keep it: it is needed to prove, and the server does not store it.</p>
          <pre>{result.secretKey}</pre>
        </div>
      {/if}
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
      <p>
        The proof shows that some snapshot leaf is yours. Its nullifier is
        Poseidon(Poseidon(secret, token), context): it does not reveal which NFT was used.
      </p>

      <div class="form">
        <label>Holder secret (from registration, 252-bit)
          <input type="text" bind:value={secretKey} placeholder="0x..." />
        </label>
        <label>NFT (same as registration)
          {#if mintStatus?.mintedTokens?.length}
            <select bind:value={tokenName}>
              {#each mintStatus.mintedTokens as t}
                <option value={t}>{t}</option>
              {/each}
            </select>
          {:else}
            <input type="text" bind:value={tokenName} />
          {/if}
        </label>
        <p>Event context: <code>{status?.event?.contextId}</code></p>
        <button onclick={generateProof} disabled={loading || !secretKey}>
          {loading ? 'Generating proof...' : 'Generate ZK Proof'}
        </button>
      </div>

      {#if result?.proof}
        <div class="result success">
          <h3>Proof Generated</h3>
          <p>Proving time: <strong>{result.provingTimeMs}ms</strong></p>
          <p>Nullifier: <code>{result.nullifier?.substring(0, 16)}...</code></p>
          <p class="note">
            Observers see the proof, the nullifier and the event; not the wallet or the NFT. A
            mempool observer could submit this proof first (front-running is not prevented).
          </p>
        </div>
      {:else if result?.error}
        <div class="result error">
          <h3>Error</h3>
          <p>{result.error}</p>
        </div>
      {/if}
    </section>

  {:else if currentPage === 'access'}
    <section>
      <h2>Step 3: Access Gated Content</h2>
      <p>
        The access transaction verifies the proof on-chain and inserts its nullifier into the
        event's sorted list. A nullifier can be inserted once.
      </p>

      {#if proofResult?.nullifier}
        <div class="form">
          <p>Nullifier from proof: <code>{proofResult.nullifier?.substring(0, 16)}...</code></p>
          <button onclick={requestAccess} disabled={loading}>
            {loading ? 'Requesting...' : 'Request Access'}
          </button>
        </div>
      {:else}
        <p>Generate a proof first (go to Prove tab).</p>
      {/if}

      {#if result?.onChainValidation}
        <div class="onchain-error">
          <h3>{result.onChainValidation.title}</h3>
          <p>{result.onChainValidation.summary}</p>
          <pre>{result.onChainValidation.detail}</pre>
        </div>
      {/if}

      {#if result?.access === true}
        <div class="result success">
          <h3>Access Granted</h3>
          <p>{result.message}</p>
          <p>Total accesses: {result.totalAccesses}</p>
        </div>
      {:else if result?.access === false}
        <div class="result error">
          <h3>Access Denied</h3>
          <p>{result.reason}</p>
        </div>
      {:else if result?.error && !result?.onChainValidation}
        <div class="result error">
          <h3>Error</h3>
          <p>{result.error}</p>
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

  input, select {
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
  .onchain-error {
    background: #2d1214;
    border: 1px solid #da3633;
    border-radius: 8px;
    padding: 16px;
    margin-top: 1rem;
  }
  .onchain-error h3 { color: #f85149; margin: 0 0 8px; }
  .onchain-error p { margin: 0 0 12px; }
  .onchain-error pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #ffb4ad;
    padding: 12px;
    max-height: 260px;
    overflow-y: auto;
  }

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
  .operator-note {
    font-size: 13px;
    color: #8b949e;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 12px;
  }
</style>
