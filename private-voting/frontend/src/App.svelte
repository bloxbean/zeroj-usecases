<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let election = $state<any>(null);
  let voteResults = $state<any>(null);
  let voteResult = $state<any>(null);
  let loading = $state(false);
  let message = $state('');
  let voteTxHashes = $state<{label: string, vote: string, txHash: string}[]>([]);

  async function loadStatus() {
    status = await api.status();
    election = await api.electionStatus();
  }

  async function castVote(voterLabel: string, vote: number) {
    loading = true;
    voteResult = null;
    message = `${voterLabel} is voting ${vote === 1 ? 'YES' : 'NO'}... (generating ZK proof + on-chain tx)`;
    try {
      const result = await api.castVote(voterLabel, vote);
      voteResult = result;
      if (result.error) {
        message = `Failed: ${result.error}`;
      } else {
        voteTxHashes = [...voteTxHashes, {
          label: voterLabel,
          vote: result.vote,
          txHash: result.txHash
        }];
        message = `${voterLabel} voted ${result.vote} — tx: ${result.txHash.substring(0, 16)}... (${result.provingTimeMs}ms)`;
      }
    } catch (e: any) {
      message = `Error: ${e.message}`;
    }
    loading = false;
  }

  async function loadResults() {
    voteResults = await api.results();
  }

  // Load on mount
  $effect(() => { loadStatus(); });
</script>

<main>
  <h1>Private Voting Demo</h1>
  <p class="subtitle">Anonymous DAO governance on Cardano with zero-knowledge proofs</p>

  <nav>
    <button class:active={currentPage === 'home'} onclick={() => { currentPage = 'home'; loadStatus(); }}>Home</button>
    <button class:active={currentPage === 'vote'} onclick={() => { currentPage = 'vote'; loadStatus(); }}>Vote</button>
    <button class:active={currentPage === 'results'} onclick={() => { currentPage = 'results'; loadResults(); }}>Results</button>
  </nav>

  {#if currentPage === 'home'}
    <section>
      <h2>Election Status</h2>
      {#if election}
        <div class="card">
          <p><strong>Election:</strong> {election.name}</p>
          <p><strong>Voters:</strong> {election.voterCount} registered</p>
          <p><strong>Finalized:</strong> {election.finalized ? 'Yes' : 'No'}</p>
          <p><strong>Tree Depth:</strong> {election.treeDepth}</p>
        </div>
        <h3>Registered Voters</h3>
        <table>
          <thead><tr><th>Label</th><th>Public Key</th><th>Address</th></tr></thead>
          <tbody>
            {#each election.voters as v}
              <tr><td>{v.label}</td><td><code>{v.publicKey}</code></td><td><code>{v.address}</code></td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p>Loading...</p>
      {/if}

      {#if status}
        <div class="card">
          <p><strong>Circuit:</strong> {status.circuit?.status} (depth {status.circuit?.treeDepth})</p>
          <p><strong>Votes cast:</strong> {status.votes?.count}</p>
          <p><strong>Mode:</strong> {status.votes?.mode}</p>
        </div>
      {/if}
    </section>

  {:else if currentPage === 'vote'}
    <section>
      <h2>Cast Your Vote</h2>
      <p>Select a voter and choose YES or NO. The ZK proof proves eligibility without revealing identity.</p>

      {#if election?.voters}
        <div class="vote-grid">
          {#each election.voters as v}
            <div class="voter-card">
              <h3>{v.label}</h3>
              <p><code>{v.publicKey}</code></p>
              <div class="vote-buttons">
                <button class="yes" onclick={() => castVote(v.label, 1)} disabled={loading}>YES</button>
                <button class="no" onclick={() => castVote(v.label, 0)} disabled={loading}>NO</button>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      {#if voteResult?.onChainValidation}
        <div class="onchain-error">
          <h3>{voteResult.onChainValidation.title}</h3>
          <p>{voteResult.onChainValidation.summary}</p>
          <pre>{voteResult.onChainValidation.detail}</pre>
        </div>
      {/if}

      {#if message}
        <div class="message">{message}</div>
      {/if}

      {#if voteTxHashes.length > 0}
        <h3>Votes Submitted On-Chain</h3>
        <table>
          <thead><tr><th>Voter</th><th>Vote</th><th>Tx Hash</th></tr></thead>
          <tbody>
            {#each voteTxHashes as vt}
              <tr>
                <td>{vt.label}</td>
                <td class={vt.vote === 'YES' ? 'vote-yes' : 'vote-no'}>{vt.vote}</td>
                <td><code>{vt.txHash.substring(0, 24)}...</code></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

  {:else if currentPage === 'results'}
    <section>
      <h2>Election Results</h2>
      {#if voteResults}
        <div class="results-bar">
          <div class="yes-bar" style="width: {voteResults.total > 0 ? (voteResults.yes / voteResults.total * 100) : 0}%">
            YES: {voteResults.yes}
          </div>
          <div class="no-bar" style="width: {voteResults.total > 0 ? (voteResults.no / voteResults.total * 100) : 0}%">
            NO: {voteResults.no}
          </div>
        </div>
        <p class="total">Total votes: {voteResults.total}</p>

        {#if voteResults.votes?.length > 0}
          <h3>Individual Votes (derived from on-chain commitments)</h3>
          <table>
            <thead><tr><th>Nullifier</th><th>Vote</th></tr></thead>
            <tbody>
              {#each voteResults.votes as v}
                <tr>
                  <td><code>{v.nullifierPrefix}</code></td>
                  <td class={v.vote === 'YES' ? 'vote-yes' : 'vote-no'}>{v.vote}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      {:else}
        <p>Loading results...</p>
      {/if}
      <button onclick={loadResults}>Refresh</button>
    </section>
  {/if}
</main>

<style>
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    max-width: 900px;
    margin: 0 auto;
    padding: 20px;
    background: #0d1117;
    color: #c9d1d9;
  }
  h1 { color: #58a6ff; margin-bottom: 4px; }
  .subtitle { color: #8b949e; margin-top: 0; }
  nav { display: flex; gap: 8px; margin: 20px 0; }
  nav button {
    padding: 8px 20px;
    border: 1px solid #30363d;
    background: #21262d;
    color: #c9d1d9;
    border-radius: 6px;
    cursor: pointer;
  }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    margin: 12px 0;
  }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; }
  code { font-size: 0.85em; color: #79c0ff; }
  .vote-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
  .voter-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }
  .voter-card h3 { margin: 0 0 8px; color: #58a6ff; }
  .vote-buttons { display: flex; gap: 8px; justify-content: center; margin-top: 12px; }
  .vote-buttons button {
    padding: 8px 24px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: bold;
    color: white;
  }
  .vote-buttons button:disabled { opacity: 0.5; cursor: not-allowed; }
  .yes { background: #238636; }
  .no { background: #da3633; }
  .onchain-error {
    background: #2d1214;
    border: 1px solid #da3633;
    border-radius: 8px;
    padding: 16px;
    margin: 16px 0;
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
  .message {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px;
    margin: 16px 0;
    color: #58a6ff;
  }
  .vote-yes { color: #3fb950; font-weight: bold; }
  .vote-no { color: #f85149; font-weight: bold; }
  .results-bar { display: flex; height: 48px; border-radius: 8px; overflow: hidden; margin: 16px 0; }
  .yes-bar { background: #238636; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; min-width: 60px; }
  .no-bar { background: #da3633; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; min-width: 60px; }
  .total { text-align: center; color: #8b949e; }
  button { cursor: pointer; }
  section { margin-top: 16px; }
</style>
