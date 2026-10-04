<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let election = $state<any>(null);
  let voteResults = $state<any>(null);
  let voteResult = $state<any>(null);
  let loading = $state(false);
  let message = $state('');
  let submissions = $state<{label: string, ballotA: string, txHash: string}[]>([]);
  let now = $state(Date.now());

  $effect(() => {
    const timer = setInterval(() => { now = Date.now(); }, 1000);
    return () => clearInterval(timer);
  });

  function short(hex: string | undefined, n = 12) {
    return hex ? hex.substring(0, n) + '…' : '';
  }

  function remaining(deadline: number) {
    const s = Math.max(0, Math.floor((deadline - now) / 1000));
    return `${Math.floor(s / 60)}m ${s % 60}s`;
  }

  async function loadStatus() {
    status = await api.status();
    election = await api.electionStatus();
  }

  async function castVote(voterLabel: string, vote: number) {
    loading = true;
    voteResult = null;
    message = `${voterLabel}: encrypting the vote, proving the ballot, submitting on-chain…`;
    try {
      const result = await api.castVote(voterLabel, vote);
      voteResult = result;
      if (result.error) {
        message = `Failed: ${result.error}`;
      } else {
        submissions = [...submissions, { label: voterLabel, ballotA: result.ballot.A.u, txHash: result.txHash }];
        message = `${voterLabel}'s encrypted ballot is on-chain — tx ${short(result.txHash, 16)} (${result.provingTimeMs} ms to prove)`;
      }
    } catch (e: any) {
      message = `Error: ${e.message}`;
    }
    loading = false;
  }

  async function loadResults() {
    voteResults = await api.results();
  }

  $effect(() => { loadStatus(); });
</script>

<main>
  <h1>Private Voting Demo</h1>
  <p class="subtitle">Encrypted ballots, a homomorphic tally and trustee decryption on Cardano</p>

  <nav>
    <button class:active={currentPage === 'home'} onclick={() => { currentPage = 'home'; loadStatus(); }}>Home</button>
    <button class:active={currentPage === 'vote'} onclick={() => { currentPage = 'vote'; loadStatus(); }}>Vote</button>
    <button class:active={currentPage === 'results'} onclick={() => { currentPage = 'results'; loadResults(); }}>Results</button>
  </nav>

  {#if currentPage === 'home'}
    <section>
      <h2>Election</h2>
      {#if election}
        <div class="card">
          <p><strong>Election:</strong> {election.name}</p>
          <p><strong>Voters:</strong> {election.voterCount} registered (Merkle depth {election.treeDepth})</p>
          {#if election.votingDeadline > 0}
            <p><strong>Voting closes:</strong> {new Date(election.votingDeadline).toLocaleTimeString()}
              {#if election.votingDeadline > now}({remaining(election.votingDeadline)} left){:else}(closed){/if}</p>
          {/if}
          <p><strong>Election key:</strong> <code>{short(election.electionKey?.u, 20)}</code> = sum of the trustees' keys</p>
        </div>
        <h3>Trustees</h3>
        <p class="hint">Each trustee holds one share of the decryption key and proved possession of it.
          All of them are needed to decrypt the tally; none can decrypt a single ballot alone.</p>
        <table>
          <thead><tr><th>Trustee</th><th>Public key share</th></tr></thead>
          <tbody>
            {#each election.trustees ?? [] as t}
              <tr><td>{t.label}</td><td><code>{short(t.publicKey.u, 24)}</code></td></tr>
            {/each}
          </tbody>
        </table>
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
          <p><strong>Ballot circuit:</strong> {status.circuit?.ballotConstraints} constraints (depth {status.circuit?.treeDepth})</p>
          <p><strong>Ballots on-chain:</strong> {status.votes?.count} ({status.votes?.mode})</p>
        </div>
      {/if}
    </section>

  {:else if currentPage === 'vote'}
    <section>
      <h2>Cast Your Vote</h2>
      <p>The vote is encrypted under the election key. The ZK proof shows the voter is eligible, has not
        voted before, and that the ciphertext holds a 0 or a 1 — without revealing which.</p>

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

      {#if submissions.length > 0}
        <h3>Ballots Submitted On-Chain</h3>
        <p class="hint">This is all anyone can see: an encrypted ballot per voter. Nobody — not the
          trustees, not an observer — can open a single one.</p>
        <table>
          <thead><tr><th>Voter</th><th>Encrypted ballot (A.u)</th><th>Tx Hash</th></tr></thead>
          <tbody>
            {#each submissions as s}
              <tr>
                <td>{s.label}</td>
                <td><code>{short(s.ballotA, 20)}</code></td>
                <td><code>{short(s.txHash, 24)}</code></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

  {:else if currentPage === 'results'}
    <section>
      <h2>Election Results</h2>
      {#if voteResults?.error}
        <p>{voteResults.error}</p>
      {:else if voteResults}
        {#if voteResults.phase === 'voting-open'}
          <div class="card">
            <p><strong>Voting is open.</strong> {voteResults.ballots} encrypted ballot(s) on-chain.</p>
            <p>The tally is decrypted once, after voting closes at
              {new Date(voteResults.votingDeadline).toLocaleTimeString()}
              {#if voteResults.votingDeadline > now}({remaining(voteResults.votingDeadline)} left){/if}.
              Decrypting earlier would let anyone diff two tallies and learn a single vote.</p>
            <p><strong>Encrypted running sum:</strong> <code>A {short(voteResults.aggregate?.A?.u, 16)}</code>
              <code>B {short(voteResults.aggregate?.B?.u, 16)}</code></p>
          </div>
        {:else}
          <div class="results-bar">
            <div class="yes-bar" style="width: {voteResults.total > 0 ? (voteResults.yes / voteResults.total * 100) : 0}%">
              YES: {voteResults.yes}
            </div>
            <div class="no-bar" style="width: {voteResults.total > 0 ? (voteResults.no / voteResults.total * 100) : 0}%">
              NO: {voteResults.no}
            </div>
          </div>
          <p class="total">Total ballots: {voteResults.total}</p>
          <div class="card">
            <p><strong>{voteResults.verified ? 'Verified' : 'NOT VERIFIED'}</strong> — re-checked from chain data and the election manifest:</p>
            <ul class="checks">
              {#each voteResults.checks ?? [] as c}
                <li class={c.startsWith('ok') ? 'vote-yes' : 'vote-no'}>{c}</li>
              {/each}
            </ul>
          </div>
          <h3>Trustee Decryption Shares</h3>
          <table>
            <thead><tr><th>Trustee</th><th>Share D = [sk]·ΣA</th><th>Proof</th></tr></thead>
            <tbody>
              {#each voteResults.shares ?? [] as s}
                <tr><td>{s.trustee}</td><td><code>{short(s.share.u, 20)}</code></td><td>Groth16 (DLEQ)</td></tr>
              {/each}
            </tbody>
          </table>
        {/if}

        {#if voteResults.encryptedBallots?.length > 0}
          <h3>Encrypted Ballots (as stored on-chain)</h3>
          <table>
            <thead><tr><th>Nullifier</th><th>A.u</th><th>B.u</th></tr></thead>
            <tbody>
              {#each voteResults.encryptedBallots as b}
                <tr>
                  <td><code>{b.nullifier}</code></td>
                  <td><code>{short(b.A.u, 16)}</code></td>
                  <td><code>{short(b.B.u, 16)}</code></td>
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
  .hint { color: #8b949e; font-size: 0.9em; }
  .checks { margin: 8px 0 0; padding-left: 20px; font-family: monospace; font-size: 0.85em; }
  button { cursor: pointer; }
  section { margin-top: 16px; }
</style>
