<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let verifyResult = $state<any>(null);
  let lockResult = $state<any>(null);
  let unlockResult = $state<any>(null);
  let loading = $state(false);
  let message = $state('');

  async function loadStatus() { status = await api.status(); }

  async function verifyUser(name: string) {
    loading = true;
    message = `Generating ZK proof for ${name}...`;
    verifyResult = null;
    try {
      verifyResult = await api.verify(name);
      message = verifyResult.error
        ? `${name}: ${verifyResult.error || verifyResult.reason}`
        : `${name}: ${verifyResult.eligible ? 'ELIGIBLE' : 'NOT ELIGIBLE'} (${verifyResult.provingTimeMs}ms)`;
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function lockFunds() {
    loading = true;
    message = 'Locking 5 ADA at credential-gated script...';
    try {
      lockResult = await api.lock(5);
      message = lockResult.error ? lockResult.error : `Locked 5 ADA — tx: ${lockResult.txHash?.substring(0, 20)}...`;
      loadStatus();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function unlockFunds(name: string) {
    loading = true;
    message = `Unlocking with ${name}'s proof...`;
    try {
      unlockResult = await api.unlock(name);
      message = unlockResult.error
        ? `Failed: ${unlockResult.error}`
        : `Unlocked! tx: ${unlockResult.txHash?.substring(0, 20)}...`;
      loadStatus();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function verifyAndUnlock(name: string, forceOnChain: boolean) {
    loading = true;
    message = `Generating ZK proof for ${name}...`;
    unlockResult = null;
    try {
      const vr = await api.verify(name);
      if (vr.error || vr.reason) {
        message = `${name}: ${vr.error || vr.reason}`;
        loading = false;
        return;
      }
      message = `${name}: ${vr.eligible ? 'ELIGIBLE' : 'NOT ELIGIBLE'} (${vr.provingTimeMs}ms). ${vr.eligible ? 'Unlocking...' : 'Attempting on-chain unlock (will be rejected by validator)...'}`;

      const ur = await fetch('/api/credential/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, forceOnChain }),
      }).then(r => r.json());

      if (ur.txHash) {
        message = `${name}: Unlocked! tx: ${ur.txHash.substring(0, 20)}...`;
        unlockResult = ur;
      } else {
        message = `${name}: REJECTED${ur.onChainRejection ? ' by on-chain validator' : ''} — ${ur.error?.substring(0, 120)}...`;
        unlockResult = ur;
      }
      loadStatus();
    } catch (e: any) {
      message = `Error: ${e.message}`;
    }
    loading = false;
  }

  $effect(() => { loadStatus(); });
</script>

<main>
  <h1>Identity KYC Demo</h1>
  <p class="subtitle">Privacy-preserving credential verification on Cardano</p>

  <nav>
    <button class:active={currentPage === 'home'} onclick={() => { currentPage = 'home'; loadStatus(); }}>Credentials</button>
    <button class:active={currentPage === 'verify'} onclick={() => { currentPage = 'verify'; loadStatus(); }}>Verify</button>
    <button class:active={currentPage === 'access'} onclick={() => { currentPage = 'access'; loadStatus(); }}>On-Chain Access</button>
  </nav>

  {#if currentPage === 'home'}
    <section>
      <h2>Issued Credentials</h2>
      <p>5 test users with KYC credentials. Eligibility: age >= {status?.minAge ?? 18} + country in approved list.</p>
      {#if status?.users}
        <table>
          <thead><tr><th>Name</th><th>Age</th><th>Country</th><th>Credential</th><th>Expected</th></tr></thead>
          <tbody>
            {#each status.users as u}
              <tr>
                <td>{u.name}</td>
                <td>{u.age}</td>
                <td>{u.countryCode}</td>
                <td><code>{u.credentialHash}</code></td>
                <td class={u.expectedEligible ? 'ok' : 'fail'}>{u.expectedEligible ? 'ELIGIBLE' : 'NOT ELIGIBLE'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

  {:else if currentPage === 'verify'}
    <section>
      <h2>Verify Credential (ZK Proof)</h2>
      <p>Select a user to generate a ZK proof. The proof reveals ONLY "eligible: yes/no" — age, country, and identity stay hidden.</p>
      {#if status?.users}
        <div class="user-grid">
          {#each status.users as u}
            <div class="user-card">
              <h3>{u.name}</h3>
              <p>Age: {u.age} | Country: {u.countryCode}</p>
              <button onclick={() => verifyUser(u.name)} disabled={loading}>
                Verify
              </button>
            </div>
          {/each}
        </div>
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
      {#if verifyResult && !verifyResult.error}
        <div class="result" class:eligible={verifyResult.eligible} class:ineligible={!verifyResult.eligible}>
          <h3>{verifyResult.name}: {verifyResult.eligible ? 'ELIGIBLE' : 'NOT ELIGIBLE'}</h3>
          {#if verifyResult.provingTimeMs}<p>Proof generated in {verifyResult.provingTimeMs}ms</p>{/if}
          {#if verifyResult.reason}<p>{verifyResult.reason}</p>{/if}
        </div>
      {/if}
    </section>

  {:else if currentPage === 'access'}
    <section>
      <h2>On-Chain Credential-Gated Access</h2>
      <p>Lock ADA at a script address. Only users with a valid ZK credential proof can unlock.</p>

      <div class="actions">
        <div class="card">
          <h3>1. Lock Funds</h3>
          <p>Lock 5 ADA at the credential-gated script.</p>
          <button onclick={lockFunds} disabled={loading}>Lock 5 ADA</button>
          <p>Locked UTXOs: {status?.lockedUtxos ?? 0}</p>
        </div>

        <div class="card">
          <h3>2. Verify + Unlock</h3>
          <p>Eligible users unlock successfully. Ineligible users are <strong>rejected by the on-chain validator</strong>.</p>
          {#if status?.users}
            <div class="unlock-buttons">
              {#each status.users as u}
                <button
                  class={u.expectedEligible ? 'btn-eligible' : 'btn-ineligible'}
                  onclick={() => verifyAndUnlock(u.name, !u.expectedEligible)}
                  disabled={loading}>
                  {u.expectedEligible ? '✓' : '✗'} {u.name} ({u.age}, {u.countryCode})
                </button>
              {/each}
            </div>
            <p class="hint">Green = expected eligible. Red = expected to fail on-chain.</p>
          {/if}
        </div>
      </div>

      {#if unlockResult?.onChainValidation}
        <div class="onchain-error">
          <h3>{unlockResult.onChainValidation.title}</h3>
          <p>{unlockResult.onChainValidation.summary}</p>
          <pre>{unlockResult.onChainValidation.detail}</pre>
        </div>
      {/if}

      {#if message}<div class="message">{message}</div>{/if}
    </section>
  {/if}
</main>

<style>
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    max-width: 900px; margin: 0 auto; padding: 20px;
    background: #0d1117; color: #c9d1d9;
  }
  h1 { color: #58a6ff; margin-bottom: 4px; }
  .subtitle { color: #8b949e; margin-top: 0; }
  nav { display: flex; gap: 8px; margin: 20px 0; }
  nav button { padding: 8px 20px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; }
  code { font-size: 0.85em; color: #79c0ff; }
  .ok { color: #3fb950; font-weight: bold; }
  .fail { color: #f85149; font-weight: bold; }
  .user-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
  .user-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
  .user-card h3 { margin: 0 0 8px; color: #58a6ff; }
  .user-card button { margin-top: 8px; padding: 8px 20px; border: none; border-radius: 6px; background: #238636; color: white; cursor: pointer; font-weight: bold; }
  .user-card button:disabled { opacity: 0.5; }
  .message { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin: 16px 0; color: #58a6ff; }
  .onchain-error { background: #2d1214; border: 1px solid #da3633; border-radius: 8px; padding: 16px; margin: 16px 0; }
  .onchain-error h3 { color: #f85149; margin: 0 0 8px; }
  .onchain-error p { margin: 0 0 12px; }
  .onchain-error pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #ffb4ad; padding: 12px; max-height: 260px; overflow-y: auto; }
  .result { border-radius: 8px; padding: 16px; margin: 16px 0; }
  .eligible { background: #0d2818; border: 1px solid #238636; }
  .ineligible { background: #2d1214; border: 1px solid #da3633; }
  .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 16px 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
  .card h3 { margin-top: 0; color: #58a6ff; }
  .card button { margin: 4px 4px 4px 0; padding: 8px 16px; border: none; border-radius: 6px; background: #1f6feb; color: white; cursor: pointer; }
  .card button:disabled { opacity: 0.5; }
  .unlock-buttons { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
  .btn-eligible { padding: 8px 16px; border: none; border-radius: 6px; background: #238636; color: white; cursor: pointer; font-weight: bold; }
  .btn-ineligible { padding: 8px 16px; border: none; border-radius: 6px; background: #da3633; color: white; cursor: pointer; font-weight: bold; }
  .btn-eligible:disabled, .btn-ineligible:disabled { opacity: 0.5; }
  .hint { font-size: 0.85em; color: #8b949e; margin-top: 4px; }
  button { cursor: pointer; }
</style>
