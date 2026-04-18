package com.bloxbean.cardano.zeroj.usecases.selective.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.selective.onchain.AdultResidentValidator;
import com.bloxbean.cardano.zeroj.usecases.selective.onchain.SeniorDoctorValidator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.List;

/**
 * On-chain gates for the two predicate DApps. Each gate is a separate
 * Cardano script address parameterized by its predicate's Groth16
 * verifying key.
 */
@Service
public class OnChainGateService {

    private static final Logger log = LoggerFactory.getLogger(OnChainGateService.class);

    private final BackendService backendService;
    private final Account adminAccount;
    private final PredicateProofService proofService;

    private PlutusScript adultScript;
    private String adultScriptAddr;
    private PlutusScript doctorScript;
    private String doctorScriptAddr;
    private boolean initialized;

    public OnChainGateService(BackendService backendService, Account adminAccount,
                              PredicateProofService proofService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.proofService = proofService;
    }

    @PostConstruct
    public synchronized void initialize() throws Exception {
        if (initialized) return;
        log.info("Compiling Adult-Resident validator...");
        var arVk = ProofCompressor.compressVk(proofService.adultResident().setup());
        adultScript = JulcScriptLoader.load(AdultResidentValidator.class,
                new BytesPlutusData(arVk.alpha()),
                new BytesPlutusData(arVk.beta()),
                new BytesPlutusData(arVk.gamma()),
                new BytesPlutusData(arVk.delta()),
                new BytesPlutusData(arVk.ic().get(0)),
                new BytesPlutusData(arVk.ic().get(1)),
                new BytesPlutusData(arVk.ic().get(2)),
                new BytesPlutusData(arVk.ic().get(3)),
                new BytesPlutusData(arVk.ic().get(4)),
                new BytesPlutusData(arVk.ic().get(5)));
        adultScriptAddr = AddressProvider.getEntAddress(adultScript, Networks.testnet()).toBech32();
        log.info("Adult-Resident gate: {}", adultScriptAddr.substring(0, 32) + "...");

        log.info("Compiling Senior-Doctor validator...");
        var sdVk = ProofCompressor.compressVk(proofService.seniorDoctor().setup());
        doctorScript = JulcScriptLoader.load(SeniorDoctorValidator.class,
                new BytesPlutusData(sdVk.alpha()),
                new BytesPlutusData(sdVk.beta()),
                new BytesPlutusData(sdVk.gamma()),
                new BytesPlutusData(sdVk.delta()),
                new BytesPlutusData(sdVk.ic().get(0)),
                new BytesPlutusData(sdVk.ic().get(1)),
                new BytesPlutusData(sdVk.ic().get(2)),
                new BytesPlutusData(sdVk.ic().get(3)),
                new BytesPlutusData(sdVk.ic().get(4)));
        doctorScriptAddr = AddressProvider.getEntAddress(doctorScript, Networks.testnet()).toBech32();
        log.info("Senior-Doctor gate: {}", doctorScriptAddr.substring(0, 32) + "...");

        initialized = true;
    }

    /** Locks ADA at the named gate. Returns tx hash. */
    public String lockGate(String gate, long lovelace) throws Exception {
        String addr = ("doctor".equals(gate)) ? doctorScriptAddr : adultScriptAddr;
        var datum = ConstrPlutusData.of(0);
        var tx = new Tx().payToContract(addr, Amount.lovelace(BigInteger.valueOf(lovelace)), datum)
                .from(adminAccount.baseAddress());
        var r = new QuickTxBuilder(backendService).compose(tx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .complete();
        if (!r.isSuccessful()) throw new RuntimeException("Lock failed: " + r.getResponse());
        log.info("Locked at {}: tx={}", gate, r.getValue());
        Thread.sleep(3000);
        return r.getValue();
    }

    public String unlockAdult(Groth16ProofBLS381 proof, BigInteger pkU, BigInteger pkV,
                              BigInteger currentYear, BigInteger countryRoot,
                              boolean eligible) throws Exception {
        return unlock(adultScript, adultScriptAddr,
                buildAdultRedeemer(proof, pkU, pkV, currentYear, countryRoot, eligible));
    }

    public String unlockDoctor(Groth16ProofBLS381 proof, BigInteger pkU, BigInteger pkV,
                               BigInteger currentYear, boolean eligible) throws Exception {
        return unlock(doctorScript, doctorScriptAddr,
                buildDoctorRedeemer(proof, pkU, pkV, currentYear, eligible));
    }

    private String unlock(PlutusScript script, String scriptAddr, PlutusData redeemer) throws Exception {
        var utxos = backendService.getUtxoService().getUtxos(scriptAddr, 10, 1);
        if (!utxos.isSuccessful() || utxos.getValue().isEmpty()) {
            throw new RuntimeException("No locked funds at " + scriptAddr.substring(0, 24) + "...");
        }
        Utxo scriptUtxo = utxos.getValue().get(0);
        var tx = new ScriptTx().collectFrom(scriptUtxo, redeemer)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(4.5))
                .attachSpendingValidator(script);
        var r = new QuickTxBuilder(backendService).compose(tx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();
        if (!r.isSuccessful()) throw new RuntimeException("Unlock failed: " + r.getResponse());
        log.info("Unlocked: tx={}", r.getValue());
        Thread.sleep(3000);
        return r.getValue();
    }

    private PlutusData buildAdultRedeemer(Groth16ProofBLS381 proof, BigInteger pkU, BigInteger pkV,
                                          BigInteger currentYear, BigInteger countryRoot, boolean eligible) {
        var c = ProofCompressor.compressProof(proof);
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(c.piA()),
                new BytesPlutusData(c.piB()),
                new BytesPlutusData(c.piC()),
                new BytesPlutusData(toMin(pkU)),
                new BytesPlutusData(toMin(pkV)),
                new BytesPlutusData(toMin(currentYear)),
                new BytesPlutusData(toMin(countryRoot)),
                new BytesPlutusData(toMin(eligible ? BigInteger.ONE : BigInteger.ZERO))
        )).build();
    }

    private PlutusData buildDoctorRedeemer(Groth16ProofBLS381 proof, BigInteger pkU, BigInteger pkV,
                                           BigInteger currentYear, boolean eligible) {
        var c = ProofCompressor.compressProof(proof);
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(c.piA()),
                new BytesPlutusData(c.piB()),
                new BytesPlutusData(c.piC()),
                new BytesPlutusData(toMin(pkU)),
                new BytesPlutusData(toMin(pkV)),
                new BytesPlutusData(toMin(currentYear)),
                new BytesPlutusData(toMin(eligible ? BigInteger.ONE : BigInteger.ZERO))
        )).build();
    }

    private static byte[] toMin(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] o = new byte[b.length - 1];
            System.arraycopy(b, 1, o, 0, o.length);
            return o;
        }
        return b;
    }

    public String getAdultGateAddress() { return adultScriptAddr; }
    public String getDoctorGateAddress() { return doctorScriptAddr; }
    public int adultGateUtxos() { return safeCount(adultScriptAddr); }
    public int doctorGateUtxos() { return safeCount(doctorScriptAddr); }

    private int safeCount(String addr) {
        try {
            var r = backendService.getUtxoService().getUtxos(addr, 100, 1);
            return (r.isSuccessful() && r.getValue() != null) ? r.getValue().size() : 0;
        } catch (Exception e) { return 0; }
    }
}
