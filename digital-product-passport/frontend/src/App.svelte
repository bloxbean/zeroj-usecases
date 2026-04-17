<script lang="ts">
  import { api } from './lib/api';

  let currentPage = $state('home');
  let status = $state<any>(null);
  let verifyResult = $state<any>(null);
  let loading = $state(false);
  let message = $state('');
  let addCount = $state(5);
  let addType = $state('battery');
  let disableOffchain = $state(false);
  let registry = $state<any>(null);

  // Pagination
  let page = $state(0);
  let pageSize = $state(20);
  let pageFilter = $state('');
  let pageData = $state<any>(null);

  async function loadStatus() { status = await api.status(); loadPage(0); }
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
      message = `Added ${r.added} ${addType} products. Total: ${r.totalProducts} products, ${r.totalBatches} batches.`;
      loadStatus(); loadPage(0);
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function verifyItem(id: string, type: string) {
    loading = true; message = `Generating ZK proofs for ${id}...`; verifyResult = null;
    try {
      verifyResult = await api.verify(id, type);
      let total = verifyResult.claims?.length || 0;
      let passed = verifyResult.claims?.filter((c: any) => c.compliant).length || 0;
      message = `${id}: ${passed}/${total} claims compliant (${verifyResult.totalProvingTimeMs}ms)`;
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function mintNft(id: string, type: string) {
    loading = true; message = `Step 1/2: Generating ZK compliance proof off-chain for ${id}...`;
    try {
      // Step 1: Off-chain ZK proof generation (pure Java Groth16 BLS12-381)
      const vr = await api.verify(id, type);
      verifyResult = vr;
      if (!vr.allCompliant && !disableOffchain) {
        message = `❌ ${id}: NOT COMPLIANT — off-chain ZK proof shows failure. Mint blocked before reaching chain. (Enable "Skip off-chain check" to test on-chain rejection)`;
        loading = false; return;
      }
      if (!vr.allCompliant && disableOffchain) {
        message = `Step 2/2: ${id} is NOT COMPLIANT but off-chain check disabled. Submitting to Cardano — on-chain validator will reject...`;
      } else {
        message = `Step 2/2: ${id} is compliant. Submitting to Cardano — on-chain Groth16 verification...`;
      }
      // Step 2: On-chain minting — Plutus V3 minting policy verifies:
      //   ✓ Manufacturer signature  ✓ Groth16 BLS12-381 pairing check  ✓ isCompliant=1  ✓ Exactly 1 token
      const mr = await fetch('/api/dpp/mint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, forceOnChain: disableOffchain }),
      }).then(r => r.json());
      if (mr.error) {
        let detail = mr.onChainRejection ? ' — REJECTED BY ON-CHAIN PLUTUS VALIDATOR' : '';
        message = mr.existingTx
          ? `⚠️ ${id}: Already minted. Existing tx: ${mr.existingTx.substring(0, 16)}...`
          : `❌ ${id}: Mint failed${detail}. ${mr.error.substring(0, 120)}`;
      } else {
        message = `✅ ${id}: DPP NFT minted! Groth16 proof verified ON-CHAIN by Plutus V3 validator. tx: ${mr.txHash?.substring(0, 20)}...`;
      }
      loadStatus(); loadPage(page);
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }

  async function anchorRoot() {
    loading = true; message = 'Anchoring minted-registry root on-chain...';
    try {
      const r = await api.anchor();
      if (r.error) { message = `Anchor failed: ${r.error}`; }
      else { message = `Root anchored! tx: ${r.txHash?.substring(0, 20)}... (${r.mintedCount} minted)`; }
      loadRegistry();
    } catch (e: any) { message = `Error: ${e.message}`; }
    loading = false;
  }
</script>

<main>
  <h1>Digital Product Passport Demo</h1>
  <p class="subtitle">EU ESPR compliance with ZK proofs on Cardano — mint DPP NFTs only when compliant</p>

  <nav>
    <button class:active={currentPage === 'home'} onclick={() => { currentPage = 'home'; pageFilter = ''; loadStatus(); }}>Products</button>
    <button class:active={currentPage === 'battery'} onclick={() => { currentPage = 'battery'; pageFilter = 'battery'; loadStatus(); }}>EV Battery</button>
    <button class:active={currentPage === 'textile'} onclick={() => { currentPage = 'textile'; pageFilter = 'textile'; loadStatus(); }}>Textile Batch</button>
    <button class:active={currentPage === 'mint'} onclick={() => { currentPage = 'mint'; pageFilter = ''; loadStatus(); }}>Mint NFT</button>
    <button class:active={currentPage === 'registry'} onclick={() => { currentPage = 'registry'; loadRegistry(); }}>Registry</button>
  </nav>

  {#if currentPage === 'home'}
    <section>
      <h2>Product Registry (Poseidon MPF + RocksDB)</h2>
      <div class="add-bar">
        <label>Add products:</label>
        <input type="number" bind:value={addCount} min="1" max="100" />
        <select bind:value={addType}>
          <option value="battery">Battery</option>
          <option value="textile">Textile Batch</option>
        </select>
        <button onclick={addProducts} disabled={loading}>Add {addCount} {addType}</button>
      </div>
      {#if status}
        <p>MPF Root: <code>{status.mpfRoot?.substring(0, 20)}...</code> | Total: {status.totalDbCount ?? (status.productCount + status.batchCount)} | Minted: {status.mintedCount}</p>
        <p>Thresholds: carbon &lt;= {status.thresholds?.carbon_kg}kg, recycled &gt;= {status.thresholds?.recycled_pct}%</p>

        <div class="filter-bar">
          <label>Filter:</label>
          <select bind:value={pageFilter} onchange={() => loadPage(0)}>
            <option value="">All</option>
            <option value="battery">Battery</option>
            <option value="textile">Textile</option>
          </select>
        </div>

        {#if pageData}
          <h3>Products (page {pageData.page + 1} of {pageData.totalPages}, {pageData.totalElements} total)</h3>
          <div class="table-scroll">
            <table>
              <thead><tr><th>Serial</th><th>Name</th><th>Type</th><th>Carbon</th><th>Recycled</th><th>Country</th><th>Units</th><th>Minted</th></tr></thead>
              <tbody>
                {#each pageData.products as p}
                  <tr>
                    <td><code>{p.serialNumber}</code></td><td>{p.name}</td><td>{p.productType}</td>
                    <td class={p.carbonKg <= status.thresholds.carbon_kg ? 'ok' : 'fail'}>{p.carbonKg}kg</td>
                    <td class={p.recycledPct >= status.thresholds.recycled_pct ? 'ok' : 'fail'}>{p.recycledPct}%</td>
                    <td>{p.country}</td>
                    <td>{p.unitCount > 0 ? p.unitCount : '—'}</td>
                    <td>{p.minted ? '✓ ' + (p.mintTxHash?.substring(0, 8) || '') + '...' : '—'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <div class="pagination">
            <button onclick={() => loadPage(page - 1)} disabled={page <= 0}>Prev</button>
            <span>Page {pageData.page + 1} of {Math.max(1, pageData.totalPages)}</span>
            <button onclick={() => loadPage(page + 1)} disabled={page >= pageData.totalPages - 1}>Next</button>
          </div>
        {/if}
      {/if}
      {#if message}<div class="message">{message}</div>{/if}
    </section>

  {:else if currentPage === 'battery'}
    <section>
      <h2>EV Battery — Per-Product Verification</h2>
      <p>Each battery gets individual ZK compliance proofs. Click Verify to generate proofs for a product.</p>
      {#if pageData}
        <div class="table-scroll">
          <table>
            <thead><tr><th>Serial</th><th>Name</th><th>Carbon</th><th>Recycled</th><th>Country</th><th>Inspections</th><th>Action</th></tr></thead>
            <tbody>
              {#each pageData.products as p}
                <tr>
                  <td><code>{p.serialNumber}</code></td><td>{p.name}</td>
                  <td class={p.carbonKg <= (status?.thresholds?.carbon_kg ?? 50) ? 'ok' : 'fail'}>{p.carbonKg}kg</td>
                  <td class={p.recycledPct >= (status?.thresholds?.recycled_pct ?? 30) ? 'ok' : 'fail'}>{p.recycledPct}%</td>
                  <td>{p.country}</td>
                  <td>{p.inspectionCount > 0 ? p.inspectionCount + '/3' : '—'}</td>
                  <td><button class="btn-action" onclick={() => verifyItem(p.serialNumber, 'product')} disabled={loading}>Verify</button></td>
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
      {#if verifyResult}
        <div class="result" class:compliant={verifyResult.allCompliant} class:noncompliant={!verifyResult.allCompliant}>
          <h3>{verifyResult.id}: {verifyResult.allCompliant ? 'ALL COMPLIANT' : 'NOT COMPLIANT'}</h3>
          {#each verifyResult.claims || [] as c}
            <p class={c.compliant ? 'ok' : 'fail'}>{c.compliant ? '✓' : '✗'} {c.claim} ({c.provingTimeMs}ms)</p>
          {/each}
        </div>
      {/if}
    </section>

  {:else if currentPage === 'textile'}
    <section>
      <h2>Textile — Per-Batch Verification</h2>
      <p>One set of proofs covers the entire batch (50-500 units). Cost-effective for high volume.</p>
      {#if pageData}
        <div class="table-scroll">
          <table>
            <thead><tr><th>Batch</th><th>Name</th><th>Units</th><th>Carbon/u</th><th>Recycled</th><th>Country</th><th>Action</th></tr></thead>
            <tbody>
              {#each pageData.products as p}
                <tr>
                  <td><code>{p.serialNumber}</code></td><td>{p.name}</td>
                  <td>{p.unitCount > 0 ? p.unitCount : '—'}</td>
                  <td class={p.carbonKg <= (status?.thresholds?.carbon_kg ?? 50) ? 'ok' : 'fail'}>{p.carbonKg}kg</td>
                  <td class={p.recycledPct >= (status?.thresholds?.recycled_pct ?? 30) ? 'ok' : 'fail'}>{p.recycledPct}%</td>
                  <td>{p.country}</td>
                  <td><button class="btn-action" onclick={() => verifyItem(p.serialNumber, 'batch')} disabled={loading}>Verify</button></td>
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
      {#if verifyResult}
        <div class="result" class:compliant={verifyResult.allCompliant} class:noncompliant={!verifyResult.allCompliant}>
          <h3>{verifyResult.id}: {verifyResult.allCompliant ? 'ALL COMPLIANT' : 'NOT COMPLIANT'}</h3>
          {#each verifyResult.claims || [] as c}
            <p class={c.compliant ? 'ok' : 'fail'}>{c.compliant ? '✓' : '✗'} {c.claim} ({c.provingTimeMs}ms)</p>
          {/each}
        </div>
      {/if}
    </section>

  {:else if currentPage === 'mint'}
    <section>
      <h2>Mint DPP NFT (On-Chain Groth16 Verification)</h2>
      <div class="note">
        <strong>How it works:</strong>
        <ol>
          <li><strong>Off-chain:</strong> ZK compliance proof generated (pure Java Groth16 BLS12-381, ~5-30s)</li>
          <li><strong>On-chain:</strong> Cardano Plutus V3 minting policy verifies the Groth16 proof via BLS12-381 pairing check + checks manufacturer signature + isCompliant=1 + exactly 1 token</li>
        </ol>
        <p>Non-compliant products are blocked at Step 1 (proof shows failure). Compliant products proceed to Step 2 where the <strong>Cardano validator enforces</strong> the proof on-chain — no one can mint without a valid ZK proof, even if they bypass this UI.</p>
      </div>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={disableOffchain} />
        <strong>Skip off-chain check</strong> — send ALL proofs (including non-compliant) to the on-chain validator. Non-compliant products will be <span class="fail">REJECTED by the Plutus validator</span>.
      </label>
      {#if pageData}
        <div class="table-scroll">
          <table>
            <thead><tr><th>Serial</th><th>Name</th><th>Type</th><th>Carbon</th><th>Recycled</th><th>Minted</th><th>Action</th></tr></thead>
            <tbody>
              {#each pageData.products as p}
                <tr class:minted-row={p.minted}>
                  <td><code>{p.serialNumber}</code></td><td>{p.name}</td><td>{p.productType}</td>
                  <td class={p.carbonKg <= (status?.thresholds?.carbon_kg ?? 50) ? 'ok' : 'fail'}>{p.carbonKg}kg</td>
                  <td class={p.recycledPct >= (status?.thresholds?.recycled_pct ?? 30) ? 'ok' : 'fail'}>{p.recycledPct}%</td>
                  <td>{p.minted ? '✓ ' + (p.mintTxHash?.substring(0, 10) || '') + '...' : '—'}</td>
                  <td>
                    {#if p.minted}
                      <span class="ok">Done</span>
                    {:else}
                      <button class="btn-mint" onclick={() => mintNft(p.serialNumber, p.productType)} disabled={loading}>Verify + Mint</button>
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
    </section>

  {:else if currentPage === 'registry'}
    <section>
      <h2>Registry (MPF State)</h2>
      {#if registry}
        <div class="registry-cards">
          <div class="card">
            <h3>Product Registry</h3>
            <p>Root: <code>{registry.productMpfRoot?.substring(0, 20)}...</code></p>
            <p>Products: {registry.productCount} | Batches: {registry.batchCount}</p>
          </div>
          <div class="card">
            <h3>Minted Registry</h3>
            <p>Root: <code>{registry.mintedMpfRoot?.substring(0, 20)}...</code></p>
            <p>Minted NFTs: {registry.mintedCount}</p>
          </div>
        </div>
        <button onclick={anchorRoot} disabled={loading}>Anchor Minted Root On-Chain</button>
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
  nav { display: flex; gap: 8px; margin: 20px 0; flex-wrap: wrap; }
  nav button { padding: 8px 18px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  nav button.active { background: #1f6feb; border-color: #1f6feb; color: white; }
  .add-bar { display: flex; gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap; }
  .add-bar input, .add-bar select { padding: 6px 10px; border: 1px solid #30363d; background: #161b22; color: #c9d1d9; border-radius: 6px; }
  .add-bar input { width: 70px; }
  .add-bar button { padding: 6px 16px; border: none; border-radius: 6px; background: #238636; color: white; cursor: pointer; }
  .table-scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.9em; }
  th { color: #8b949e; }
  code { font-size: 0.83em; color: #79c0ff; }
  .ok { color: #3fb950; font-weight: bold; }
  .fail { color: #f85149; font-weight: bold; }
  .card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; margin: 12px 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }
  .card h3 { margin: 0 0 6px; color: #58a6ff; font-size: 0.95em; }
  .card p { margin: 2px 0; font-size: 0.88em; }
  .minted-card { border-color: #238636; }
  .btn-mint { margin-top: 6px; padding: 6px 16px; border: none; border-radius: 6px; background: #1f6feb; color: white; cursor: pointer; font-weight: bold; font-size: 0.85em; }
  .btn-mint:disabled { opacity: 0.5; }
  .message { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin: 12px 0; color: #58a6ff; }
  .result { border-radius: 8px; padding: 14px; margin: 12px 0; }
  .compliant { background: #0d2818; border: 1px solid #238636; }
  .noncompliant { background: #2d1214; border: 1px solid #da3633; }
  .registry-cards { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 12px 0; }
  .hint { font-size: 0.83em; color: #8b949e; }
  .filter-bar { display: flex; gap: 8px; align-items: center; margin: 8px 0; }
  .filter-bar select { padding: 4px 8px; border: 1px solid #30363d; background: #161b22; color: #c9d1d9; border-radius: 6px; }
  .pagination { display: flex; gap: 12px; align-items: center; justify-content: center; margin: 12px 0; }
  .pagination button { padding: 6px 14px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; border-radius: 6px; cursor: pointer; }
  .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
  .pagination span { color: #8b949e; font-size: 0.9em; }
  .btn-action { padding: 4px 12px; border: none; border-radius: 5px; background: #238636; color: white; cursor: pointer; font-size: 0.83em; font-weight: bold; }
  .btn-action:disabled { opacity: 0.4; }
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
