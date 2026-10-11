package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.MultiAsset;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.spec.TransactionBody;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.transaction.spec.TransactionOutput;
import com.bloxbean.cardano.client.transaction.spec.Value;
import com.bloxbean.cardano.client.util.HexUtil;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * An unsigned passport transaction body as the manufacturer builds it, for the auditor's checks.
 * The VK is a placeholder: the auditor's checks never look at the script's code.
 */
public final class PassportTxFixture {

    public final String serial;
    public final byte[] productId;
    public final Account manufacturer;
    public final Account auditor;
    public final PassportScript script;
    public final PassportDatum expected;
    /** Where the fixture's inputs live: the manufacturer's address unless a test says otherwise. */
    public final Map<String, String> inputAddresses = new HashMap<>();

    /** Fresh keys, a placeholder-VK script, and a two-claim report. */
    public PassportTxFixture(String serial) {
        this(serial, new Account(Networks.testnet()), new Account(Networks.testnet()), null, null);
    }

    /** A given deployment ({@code script}) and report ({@code expected}); nulls get the defaults. */
    public PassportTxFixture(String serial, Account manufacturer, Account auditor, PassportScript script, PassportDatum expected) {
        this.serial = serial;
        this.productId = serial.getBytes(StandardCharsets.UTF_8);
        this.manufacturer = manufacturer;
        this.auditor = auditor;
        if (script == null) {
            byte[] g1 = new byte[48];
            byte[] g2 = new byte[96];
            var vk = new SnarkjsToCardano.VkCompressed(g1, g2, g2, g2, List.of(g1, g1, g1, g1, g1));
            script = new PassportScript(RoleKeys.pkh(manufacturer), RoleKeys.pkh(auditor), Claim.CARBON, 50, vk, Networks.testnet());
        }
        this.script = script;
        this.expected = expected != null ? expected : PassportDatum.of(productId, RoleKeys.pkh(manufacturer),
                List.of(ClaimOpening.fresh(Claim.CARBON, 7), ClaimOpening.fresh(Claim.ORIGIN, 276)));
    }

    public Function<TransactionInput, Optional<String>> addressOf() {
        return in -> Optional.ofNullable(inputAddresses.get(in.getTransactionId() + "#" + in.getIndex()));
    }

    /** A builder for the honest body, which tests then mutate. */
    public Body body() {
        return new Body();
    }

    public final class Body {
        public PlutusData datum = expected.toPlutusData();
        public String address = script.address();
        public long quantity = 1;
        public boolean extraMint;
        public boolean auditorRequired = true;
        public long ttl = 1_000;
        public List<TransactionInput> inputs = new ArrayList<>();
        public List<TransactionInput> collateral = new ArrayList<>();
        public TransactionBody.TransactionBodyBuilder extra = TransactionBody.builder();

        Body() {
            inputs.add(input("aa", 0, manufacturer.baseAddress()));
            collateral.add(input("aa", 1, manufacturer.baseAddress()));
        }

        public PassportTxFixture fixture() {
            return PassportTxFixture.this;
        }

        public TransactionInput input(String txByte, int index, String at) {
            String tx = txByte.repeat(32);
            inputAddresses.put(tx + "#" + index, at);
            return new TransactionInput(tx, index);
        }

        public Transaction build() {
            String name = "0x" + HexUtil.encodeHexString(productId);
            List<Asset> minted = new ArrayList<>(List.of(new Asset(name, BigInteger.valueOf(quantity))));
            if (extraMint) minted.add(new Asset("0x" + HexUtil.encodeHexString("OTHER".getBytes()), BigInteger.ONE));
            MultiAsset mint = MultiAsset.builder().policyId(script.policyId()).assets(minted).build();
            TransactionOutput out = TransactionOutput.builder().address(address)
                    .value(Value.builder().coin(BigInteger.valueOf(5_000_000)).multiAssets(List.of(MultiAsset.builder()
                            .policyId(script.policyId()).assets(List.of(new Asset(name, BigInteger.valueOf(quantity)))).build())).build())
                    .inlineDatum(datum).build();
            List<byte[]> signers = new ArrayList<>(List.of(RoleKeys.pkh(manufacturer)));
            if (auditorRequired) signers.add(RoleKeys.pkh(auditor));
            TransactionBody body = extra.inputs(inputs).collateral(collateral).mint(List.of(mint)).outputs(List.of(out))
                    .requiredSigners(signers).ttl(ttl).fee(BigInteger.valueOf(500_000)).build();
            return Transaction.builder().body(body).build();
        }
    }
}
