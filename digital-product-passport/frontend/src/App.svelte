<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('products');
  let status = $state<any>(null);
  let verifyResult = $state<any>(null);
  let mintResult = $state<any>(null);
  let readerResult = $state<any>(null);
  let privateView = $state<any>(null);
  let loading = $state(false);
  let message = $state('');
  let addCount = $state(5);
  let addType = $state('battery');
  let disableOffchain = $state(false);
  let registry = $state<any>(null);
  let readerId = $state('BAT-SN001');

  // Pagination
  let page = $state(0);
  let pageSize = $state(20);
  let pageFilter = $state('');
  let pageData = $state<any>(null);

  async function loadStatus() { status = await api.status(); loadPage(page); }
  async function loadRegistry() { registry = await api.registry(); }
  async function loadPage(p: number) {
    page = Math.max(0, p);
    pageData = await api.listProducts(page, pageSize, pageFilter || undefined);
  }
  $effect(() => { loadStatus(); });

  async function addProducts() {
    loading = true;
    message = `Adding ${addCount} ${addType} products...`;
    try {
      const r = await api.addProducts(addCount, addType);
      message = r.error ? `Error: ${r.error}` : `Added ${r.added} ${addType} products. Total: ${r.totalProducts}.`;
      loadStatus();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function verifyItem(id: string) {
    loading = true; verifyResult = null; mintResult = null;
    message = `${id}: the auditor commits each claim (fresh blinding), the manufacturer proves them...`;
    try {
      verifyResult = await api.verify(id);
      if (verifyResult.error) { message = `Error: ${verifyResult.error}`; }
      else {
        const total = verifyResult.claims?.length || 0;
        const proved = verifyResult.claims?.filter((c: any) => c.compliant).length || 0;
        message = `${id}: ${proved}/${total} claims proved (${verifyResult.totalProvingTimeMs} ms)`;
      }
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function mintPassport(id: string) {
    loading = true; mintResult = null;
    message = `Step 1/2: ${id}: auditor commitments and the manufacturer's proofs, off-chain...`;
    try {
      const vr = await api.verify(id);
      verifyResult = vr;
      const carbon = vr.claims?.find((c: any) => c.gatedOnChain);
      if (carbon && !carbon.compliant && !disableOffchain) {
        message = `${id}: the carbon claim cannot be proved, so no passport can be minted. (Enable "Skip off-chain check" to submit a proof against a threshold the manufacturer chose; the policy refuses it.)`;
        loading = false; return;
      }
      message = `Step 2/2: ${id}: the manufacturer builds the passport transaction, the auditor checks it against its report and co-signs, the policy verifies the carbon proof on-chain...`;
      const mr = await api.mint(id, disableOffchain);
      mintResult = mr;
      if (mr.error) {
        const detail = mr.onChainRejection ? ' REJECTED BY THE PASSPORT POLICY.' : '';
        message = mr.existingPassport
          ? `${id}: a passport already exists: ${mr.existingPassport}`
          : `${id}: mint failed.${detail} ${String(mr.error).substring(0, 160)}`;
      } else {
        message = `${id}: passport minted at ${mr.passport?.substring(0, 20)}... (claims: ${mr.claims?.join(', ')})`;
      }
      loadStatus();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function revokePassport(id: string) {
    loading = true; message = `${id}: the auditor revokes the passport (spend + burn, auditor signature only)...`;
    try {
      const r = await api.revoke(id);
      message = r.error ? `${id}: revoke failed: ${r.error}` : `${id}: revoked, tx ${r.txHash?.substring(0, 20)}...`;
      loadStatus();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function checkPassport(id: string) {
    loading = true; readerResult = null; readerId = id;
    message = `${id}: reading the passport from chain...`;
    try {
      readerResult = await api.passport(id);
      message = readerResult.accepted ? `${id}: passport accepted` : `${id}: not accepted: ${readerResult.reason}`;
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function showPrivate(id: string) {
    privateView = await api.manufacturer(id);
  }

  async function anchorRoot() {
    loading = true; message = 'Anchoring the passport registry root on-chain...';
    try {
      const r = await api.anchor();
      message = r.error ? `Anchor failed: ${r.error}` : `Root anchored: tx ${r.txHash?.substring(0, 20)}... (${r.passportCount} passports)`;
      loadRegistry();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }
</script>

<main>
  <h1>Digital Product Passport Demo</h1>
  <p class="subtitle">Product passports proved against auditor-issued Pedersen commitments on Cardano</p>
  <p class="custody">Operator view: this demo server holds the manufacturer's and the auditor's keys. Privacy holds against chain and mempool observers, not against this server.</p>

  <nav>
    <button class:active={currentPage === 'products'} onclick={() => { currentPage = 'products'; loadStatus(); }}>Products</button>
    <button class:active={currentPage === 'mint'} onclick={() => { currentPage = 'mint'; loadStatus(); }}>Issue passport</button>
    <button class:active={currentPage === 'reader'} onclick={() => { currentPage = 'reader'; }}>Reader</button>
    <button class:active={currentPage === 'registry'} onclick={() => { currentPage = 'registry'; loadRegistry(); }}>Registry</button>
  </nav>

  {#if currentPage === 'products' || currentPage === 'mint'}
    <section>
      {#if currentPage === 'products'}
        <h2>Products</h2>
        <div class="add-bar">
          <span>Add products:</span>
          <input type="number" bind:value={addCount} min="1" max="100" />
          <select bind:value={addType}>
            <option value="battery">Battery</option>
            <option value="textile">Textile Batch</option>
          </select>
          <button onclick={addProducts} disabled={loading}>Add {addCount} {addType}</button>
        </div>
      {:else}
        <h2>Issue a passport</h2>
        <div class="note">
          <ol>
            <li><strong>Auditor:</strong> measures, and commits each claim (carbon, recycled content, origin, inspections) as a <code>pedersen-jubjub-vector-v1</code> commitment with a fresh 252-bit blinding. It hands the opening to the manufacturer.</li>
            <li><strong>Manufacturer:</strong> proves each claim from the opening, off-chain (Groth16, BLS12-381).</li>
            <li><strong>One transaction:</strong> the manufacturer builds it; the auditor checks every commitment and the product id against its report, and co-signs. The <code>DppPassport</code> policy checks both signatures, the exact mint <code>{'{'}productId: 1{'}'}</code>, the passport output at its own address with the exact datum, and the carbon proof against the commitment in that datum.</li>
          </ol>
          <p>The passport datum carries the commitments, not the values. Recycled content, origin and inspections are verified off-chain against those commitments (see Reader).</p>
        </div>
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={disableOffchain} />
          <span><strong>Skip off-chain check</strong>: for a product whose carbon claim cannot be proved, submit a proof against a threshold the manufacturer chose itself. The policy fixes the threshold, so it <span class="fail">rejects</span> the transaction.</span>
        </label>
      {/if}
      {#if status}
        <p>Policy (and passport address): <code>{status.policyId?.substring(0, 20)}...</code> | Gated on-chain: {status.gatedClaim} &lt;= {status.thresholds?.carbon_kg} kg | Passports: {status.passportCount} / {status.totalDbCount}</p>
        <div class="filter-bar">
          <span>Filter:</span>
          <select bind:value={pageFilter} onchange={() => loadPage(0)}>
            <option value="">All</option>
            <option value="battery">EV battery (per product)</option>
            <option value="textile">Textile (per batch)</option>
          </select>
        </div>
      {/if}
      {#if pageData}
        <div class="table-scroll">
          <table>
            <thead><tr><th>Serial</th><th>Name</th><th>Type</th><th>Units</th><th>Passport</th><th>Actions</th></tr></thead>
            <tbody>
              {#each pageData.products as p}
                <tr class:minted-row={p.minted}>
                  <td><code>{p.serialNumber}</code></td><td>{p.name}</td><td>{p.productType}</td>
                  <td>{p.unitCount > 0 ? p.unitCount : '—'}</td>
                  <td>{p.passport ? p.passport.substring(0, 12) + '...' : (p.revoked ? 'revoked' : '—')}</td>
                  <td class="actions">
                    {#if currentPage === 'products'}
                      <button class="btn-action" onclick={() => verifyItem(p.serialNumber)} disabled={loading}>Verify</button>
                      <button class="btn-plain" onclick={() => showPrivate(p.serialNumber)} disabled={loading}>Private</button>
                      {#if p.passport}<button class="btn-plain" onclick={() => { currentPage = 'reader'; checkPassport(p.serialNumber); }} disabled={loading}>Check</button>{/if}
                    {:else if p.minted}
                      <button class="btn-plain" onclick={() => revokePassport(p.serialNumber)} disabled={loading}>Revoke (auditor)</button>
                    {:else}
                      <button class="btn-mint" onclick={() => mintPassport(p.serialNumber)} disabled={loading}>Verify + Mint</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <button onclick={() => loadPage(page - 1)} disabled={page <= 0}>Prev</button>
          <span>Page {pageData.page + 1} of {Math.max(1, pageData.totalPages)} ({pageData.totalElements} total)</span>
          <button onclick={() => loadPage(page + 1)} disabled={page >= pageData.totalPages - 1}>Next</button>
        </div>
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
      {#if verifyResult && !verifyResult.error}
        <div class="result" class:compliant={verifyResult.allCompliant} class:noncompliant={!verifyResult.allCompliant}>
          <h3>{verifyResult.id}: {verifyResult.allCompliant ? 'every claim proved' : 'not every claim can be proved'}</h3>
          {#each verifyResult.claims || [] as c}
            <p class={c.compliant ? 'ok' : 'fail'}>{c.compliant ? '✓' : '✗'} {c.claim}: {c.statement}{c.gatedOnChain ? ' (verified on-chain at mint)' : ' (verified off-chain)'} ({c.provingTimeMs} ms)</p>
          {/each}
        </div>
      {/if}
      {#if mintResult?.onChainValidation}
        <div class="onchain-error">
          <h3>{mintResult.onChainValidation.title}</h3>
          <p>{mintResult.onChainValidation.summary}</p>
          <pre>{mintResult.onChainValidation.detail}</pre>
        </div>
      {/if}
      {#if privateView && currentPage === 'products'}
        <div class="private">
          <h3>Manufacturer (private): {privateView.id}</h3>
          <p class="hint">The manufacturer's own values. They are not in any public response, in the passport datum or in the registry.</p>
          {#if privateView.values}
            <table>
              <tbody>
                <tr><td>carbon_kg</td><td>{privateView.values.carbon_kg}</td></tr>
                <tr><td>recycled_pct</td><td>{privateView.values.recycled_pct}</td></tr>
                <tr><td>country</td><td>{privateView.values.country}</td></tr>
                <tr><td>inspections (inspector:time)</td><td>{privateView.values.inspections ?? '—'}</td></tr>
              </tbody>
            </table>
          {/if}
          <button class="btn-plain" onclick={() => privateView = null}>Close</button>
        </div>
      {/if}
    </section>

  {:else if currentPage === 'reader'}
    <section>
      <h2>Reader: check a passport from the chain</h2>
      <div class="note">
        <p>The reader finds the passport token at the passport address, refuses a product whose mint history shows more than one passport, and verifies each off-chain claim proof against the commitment in the passport datum. It takes each claim's schema digest σ from its own registry and compares it with the datum's; it never takes σ from the datum.</p>
      </div>
      <div class="add-bar">
        <input class="wide" bind:value={readerId} placeholder="product id" />
        <button onclick={() => checkPassport(readerId)} disabled={loading}>Check</button>
      </div>
      {#if message}<div class="message">{message}</div>{/if}
      {#if readerResult}
        <div class="result" class:compliant={readerResult.accepted} class:noncompliant={!readerResult.accepted}>
          <h3>{readerResult.id}: {readerResult.accepted ? 'accepted' : 'not accepted'} {readerResult.status ? '(' + readerResult.status + ')' : ''}</h3>
          {#if readerResult.passport}<p>Passport: <code>{readerResult.passport}</code></p>{/if}
          {#if readerResult.reason}<p>{readerResult.reason}</p>{/if}
          {#each readerResult.claims || [] as c}
            <p class={c.verdict?.startsWith('VERIFIED') ? 'ok' : 'fail'}>{c.claim}: {c.statement}: {c.verdict}</p>
          {/each}
        </div>
      {/if}
    </section>

  {:else if currentPage === 'registry'}
    <section>
      <h2>Passport registry (Poseidon MPF)</h2>
      <p class="hint">The registry stores <code>productId → passport outref</code> and nothing else. The measurements stay in the manufacturer's database.</p>
      {#if registry}
        <div class="registry-cards">
          <div class="card">
            <h3>Registry</h3>
            <p>Root: <code>{registry.registryRoot?.substring(0, 20)}...</code></p>
            <p>Passports: {registry.passportCount} | Products: {registry.productCount}</p>
          </div>
        </div>
        <button onclick={anchorRoot} disabled={loading}>Anchor registry root on-chain</button>
      {:else}
        <p>Loading...</p>
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
    </section>
  {/if}
</main>

<style>
  :global(body) { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1050px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; margin-bottom: 4px; }
  .subtitle { color: #8b949e; margin-top: 0; }
  .custody { color: #d29922; font-size: 0.85em; margin: 4px 0 0; }
  nav { display: flex; gap: 8px; margin: 20px 0; flex-wrap: wrap; }
  nav button { padding: 8px 18px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }
  .add-bar { display: flex; gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap; }
  .add-bar input, .add-bar select { padding: 6px 10px; border: 1px solid #30363d; background: #161b22; color: #c9d1d9; border-radius: 6px; }
  .add-bar input { width: 70px; }
  .add-bar input.wide { width: 220px; }
  .add-bar button { padding: 6px 16px; border: none; border-radius: 6px; background: #238636; color: white; cursor: pointer; }
  .table-scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.9em; }
  th { color: #8b949e; }
  code { font-size: 0.83em; color: #79c0ff; }
  .ok { color: #3fb950; font-weight: bold; }
  .fail { color: #f85149; font-weight: bold; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }
  .card h3 { margin: 0 0 6px; color: #58a6ff; font-size: 0.95em; }
  .card p { margin: 2px 0; font-size: 0.88em; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .btn-mint { padding: 4px 12px; border: none; border-radius: 6px; background: #1f6feb; color: white; cursor: pointer; font-weight: bold; font-size: 0.83em; }
  .btn-plain { padding: 4px 12px; border: 1px solid #30363d; border-radius: 6px; background: #21262d; color: #c9d1d9; cursor: pointer; font-size: 0.83em; }
  .btn-action { padding: 4px 12px; border: none; border-radius: 5px; background: #238636; color: white; cursor: pointer; font-size: 0.83em; font-weight: bold; }
  .onchain-error { background: #2d1214; border: 1px solid #da3633; border-radius: 8px; padding: 16px; margin: 16px 0; }
  .onchain-error h3 { color: #f85149; margin: 0 0 8px; }
  .onchain-error p { margin: 0 0 12px; }
  .onchain-error pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #ffb4ad; padding: 12px; max-height: 260px; overflow-y: auto; }
  .message { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin: 12px 0; color: #58a6ff; }
  .result { border-radius: 8px; padding: 14px; margin: 12px 0; }
  .compliant { background: #0d2818; border: 1px solid #238636; }
  .noncompliant { background: #2d1214; border: 1px solid #da3633; }
  .private { background: #1c1208; border: 1px solid #d29922; border-radius: 8px; padding: 14px; margin: 12px 0; }
  .private h3 { color: #d29922; margin: 0 0 6px; }
  .registry-cards { display: grid; grid-template-columns: 1fr; gap: 12px; margin: 12px 0; }
  .hint { font-size: 0.83em; color: #8b949e; }
  .filter-bar { display: flex; gap: 8px; align-items: center; margin: 8px 0; }
  .filter-bar select { padding: 4px 8px; border: 1px solid #30363d; background: #161b22; color: #c9d1d9; border-radius: 6px; }
  .pagination { display: flex; gap: 12px; align-items: center; justify-content: center; margin: 12px 0; }
  .pagination button { padding: 6px 14px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
  .pagination span { color: #8b949e; font-size: 0.9em; }
  .minted-row { background: #0d2818; }
  .note { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #1f6feb; border-radius: 6px; padding: 12px 16px; margin: 12px 0; font-size: 0.88em; }
  .note ol { margin: 6px 0; padding-left: 20px; }
  .note li { margin: 4px 0; }
  .note p { margin: 6px 0 0; color: #8b949e; }
  .checkbox-label { display: flex; align-items: flex-start; gap: 8px; margin: 12px 0; padding: 10px 14px; background: #1c1208; border: 1px solid #d29922; border-radius: 6px; font-size: 0.88em; cursor: pointer; }
  .checkbox-label input { margin-top: 3px; }
  button { cursor: pointer; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
