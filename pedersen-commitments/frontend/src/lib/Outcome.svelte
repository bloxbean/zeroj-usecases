<script lang="ts">
  // Shows the result of the last action: success with its transaction, "no proof possible",
  // or a validator rejection (like private-voting's on-chain validation panel).
  let { result }: { result: any } = $props();
</script>

{#if result}
  {#if result.ok}
    <div class="ok">
      ✓ {result.data.summary ?? result.data.verdict ?? result.data.lenderLearns ?? 'Done'}
      {#if result.data.txHash}<br /><code>tx {result.data.txHash}</code>{/if}
    </div>
  {:else if result.data?.noProof}
    <div class="noproof">
      <h4>No proof possible</h4>
      <p>{result.data.error}</p>
      <p class="hint">The statement is false, so the prover cannot produce a proof. Nothing reaches the chain.</p>
    </div>
  {:else if result.data?.onChainValidation}
    <div class="rejected">
      <h4>{result.data.onChainValidation.title}</h4>
      <p>{result.data.onChainValidation.summary}</p>
      <pre>{result.data.onChainValidation.detail}</pre>
    </div>
  {:else}
    <div class="rejected"><p>{result.data?.error ?? 'Failed'}</p></div>
  {/if}
{/if}

<style>
  .ok { background: #12261a; border: 1px solid #238636; border-radius: 8px; padding: 10px 14px; margin: 12px 0; color: #7ee787; }
  .noproof { background: #2b2111; border: 1px solid #d29922; border-radius: 8px; padding: 10px 14px; margin: 12px 0; }
  .noproof h4 { color: #e3b341; margin: 0 0 6px; }
  .rejected { background: #2d1214; border: 1px solid #da3633; border-radius: 8px; padding: 10px 14px; margin: 12px 0; }
  .rejected h4 { color: #f85149; margin: 0 0 6px; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 200px; overflow-y: auto; background: #161b22; padding: 8px; border-radius: 6px; color: #ffb4ad; font-size: 0.8em; }
  p { margin: 4px 0; }
  .hint { color: #8b949e; font-size: 0.9em; }
  code { font-size: 0.85em; color: #79c0ff; overflow-wrap: anywhere; }
</style>
