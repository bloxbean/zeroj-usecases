package com.bloxbean.cardano.zeroj.usecases.recovery.ui.verify;

import com.bloxbean.cardano.zeroj.usecases.recovery.cli.Flows;
import javafx.animation.PauseTransition;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.Separator;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

import java.nio.file.Path;

/**
 * The "Verify" screen. Off-chain: the pure-Java pairing check (sub-second). On-chain: an
 * admin/funding wallet locks a gate UTxO and unlocks it with the proof, so the ledger runs the
 * verifier — pick the network and supply a funding mnemonic (and, off devnet, a Blockfrost key).
 * Both run on background {@link Task}s so the UI stays responsive.
 */
public final class VerifyView {

    private final Path bundleDir;
    private final Path proofDir;
    private final Runnable onBack;

    private final ProgressBar bar = new ProgressBar(0);
    private final Label result = new Label();
    private final Button verify = new Button("Verify off-chain");
    private final Button verifyOnChain = new Button("Verify on-chain");

    // Verify targets — common to off-chain and on-chain. Prefilled from public-inputs.json; the
    // proof is checked against exactly these (edit to confirm against an address you know).
    private final TextField addressField = new TextField();
    private final TextField recipientField = new TextField();

    private final ComboBox<String> networkBox =
            new ComboBox<>(FXCollections.observableArrayList("devnet", "preview", "preprod", "mainnet"));
    private final PasswordField adminMnemonic = new PasswordField();
    private final TextField bfKeyField = new TextField();
    private final TextField bfUrlField = new TextField();

    // on-chain result: copyable tx hash + validator address (hidden until a successful verify)
    private final TextField txHashField = readOnlyField();
    private final TextField scriptField = readOnlyField();
    private final VBox onchainResult = new VBox(8);

    public VerifyView(Path bundleDir, Path proofDir, Runnable onBack) {
        this.bundleDir = bundleDir;
        this.proofDir = proofDir;
        this.onBack = onBack;
    }

    public Parent build() {
        var title = new Label("Verify a proof");
        title.getStyleClass().add("title");

        var info = new Label("Proof: " + proofDir.resolve("proof.json").toAbsolutePath());
        info.setWrapText(true);
        info.getStyleClass().add("hint");

        bar.setMaxWidth(Double.MAX_VALUE);
        result.setWrapText(true);
        result.getStyleClass().add("status");

        boolean ready = Flows.hasProof(proofDir) && Flows.hasKeys(bundleDir);
        verify.setDisable(!ready);
        verifyOnChain.setDisable(!ready);
        result.setText(!Flows.hasKeys(bundleDir) ? "No key bundle found — download or generate keys first."
                : !Flows.hasProof(proofDir) ? "No proof found — generate one on the Prove screen first."
                : "Ready to verify.");
        verify.setOnAction(e -> startOffChain());
        verifyOnChain.setOnAction(e -> startOnChain());

        // Verify-target fields, prefilled from the proof folder. Both verify buttons check against
        // these exact values, so a mismatched (or edited) address/recipient makes verification fail.
        addressField.setPromptText("address the proof is for (bech32)");
        recipientField.setPromptText("recipient the payout must go to (bech32)");
        if (Flows.hasProof(proofDir)) {
            try {
                String a = Flows.proofAddress(proofDir);
                String r = Flows.proofRecipient(proofDir);
                if (a != null) addressField.setText(a);
                if (r != null) recipientField.setText(r);
            } catch (Exception ignore) { /* best-effort prefill */ }
        }
        var targetsHint = new Label("The proof is verified against these. Prefilled from the proof — "
                + "edit to confirm it's for an address and recipient you expect.");
        targetsHint.setWrapText(true);
        targetsHint.getStyleClass().add("hint");
        var targets = new VBox(6, fieldLabel("Address (proven)"), addressField,
                fieldLabel("Recipient"), recipientField, targetsHint);

        // ---- on-chain inputs ----
        networkBox.setValue("devnet");
        adminMnemonic.setPromptText("funding wallet mnemonic (NOT the proven wallet)");
        bfKeyField.setPromptText("Blockfrost project id (needed off devnet)");
        bfUrlField.setPromptText("endpoint override (optional; e.g. DevKit on host)");

        var demo = new Label("⚠ Demo flow. The validator verifies the proof AND enforces the payout "
                + "goes to the recipient — but here a funding wallet locks and unlocks a gate UTxO to "
                + "demonstrate on-chain verification, not a production refund orchestration.");
        demo.setWrapText(true);
        demo.getStyleClass().add("warn");

        var onchainHint = new Label("On-chain: a funding wallet locks a gate UTxO and unlocks it with "
                + "your proof (~5 s, ~1 ADA). Use a low-value wallet — on devnet it is auto-funded.");
        onchainHint.setWrapText(true);
        onchainHint.getStyleClass().add("hint");

        // copyable result (shown after a successful on-chain verify)
        onchainResult.getChildren().addAll(
                copyRow("Tx hash", txHashField),
                copyRow("Validator", scriptField));
        onchainResult.setVisible(false);
        onchainResult.setManaged(false);

        var netRow = new HBox(8, fieldLabel("Network"), networkBox);
        netRow.setAlignment(Pos.CENTER_LEFT);

        var back = new Button("Back");
        back.setOnAction(e -> onBack.run());
        back.getStyleClass().add("ghost");

        // Result (status + copyable tx hash / validator) sits at the TOP, under the title, so it is
        // always visible after a verify — never hidden below the on-chain form.
        var box = new VBox(12, title, info, targets, bar, result, onchainResult, verify,
                new Separator(),
                section("Verify on-chain"), demo, onchainHint,
                netRow,
                fieldLabel("Funding wallet mnemonic"), adminMnemonic,
                fieldLabel("Blockfrost key (optional)"), bfKeyField,
                fieldLabel("Endpoint URL (optional)"), bfUrlField,
                new HBox(10, verifyOnChain, back));
        box.setAlignment(Pos.TOP_LEFT);
        return box;
    }

    /** A read-only value field with a Copy button that puts it on the system clipboard. */
    private HBox copyRow(String label, TextField valueField) {
        var copy = new Button("Copy");
        copy.getStyleClass().add("secondary");
        copy.setOnAction(e -> {
            var content = new ClipboardContent();
            content.putString(valueField.getText());
            Clipboard.getSystemClipboard().setContent(content);
            copy.setText("Copied");
            var revert = new PauseTransition(Duration.seconds(1.2));
            revert.setOnFinished(ev -> copy.setText("Copy"));
            revert.play();
        });
        HBox.setHgrow(valueField, Priority.ALWAYS);
        var row = new HBox(8, fieldLabel(label), valueField, copy);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private static TextField readOnlyField() {
        var f = new TextField();
        f.setEditable(false);
        return f;
    }

    private void startOffChain() {
        final String address = addressField.getText();
        final String recipient = recipientField.getText();
        var task = new Task<Boolean>() {
            @Override protected Boolean call() throws Exception {
                return Flows.verifyOffChain(bundleDir, proofDir, address, recipient);
            }
        };
        bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        result.setText("Verifying off-chain…");
        resultStyle(null);
        showResultDetails(false);
        buttons(true);
        task.setOnSucceeded(e -> {
            bar.setProgress(0); buttons(false);
            boolean ok = Boolean.TRUE.equals(task.getValue());
            result.setText(ok ? "✓ VALID — the proof is for " + address + " → recipient " + recipient + "."
                              : "✗ INVALID — the proof did not verify for that address/recipient.");
            resultStyle(ok ? "success" : "danger");
        });
        task.setOnFailed(e -> fail(task, "Verification error"));
        run(task, "verify-offchain");
    }

    private void startOnChain() {
        String m = adminMnemonic.getText();
        if (m == null || m.isBlank()) { resultStyle("danger"); result.setText("Enter the funding wallet mnemonic."); return; }
        final char[] mnemonicChars = m.toCharArray();
        adminMnemonic.clear();
        final String network = networkBox.getValue();
        final String bfKey = bfKeyField.getText();
        final String bfUrl = bfUrlField.getText();
        final String address = addressField.getText();
        final String recipient = recipientField.getText();

        var task = new Task<Flows.OnChainResult>() {
            @Override protected Flows.OnChainResult call() throws Exception {
                return Flows.verifyOnChain(bundleDir, proofDir, mnemonicChars, network, bfKey, bfUrl,
                        address, recipient, this::updateMessage);
            }
        };
        bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        result.textProperty().bind(task.messageProperty());
        resultStyle(null);
        showResultDetails(false);
        buttons(true);
        task.setOnSucceeded(e -> {
            result.textProperty().unbind();
            bar.setProgress(0); buttons(false);
            var r = task.getValue();
            resultStyle("success");
            result.setText("✓ VERIFIED ON-CHAIN");
            txHashField.setText(r.txHash());
            scriptField.setText(r.scriptAddress());
            showResultDetails(true);
        });
        task.setOnFailed(e -> { result.textProperty().unbind(); fail(task, "On-chain verification failed"); });
        run(task, "verify-onchain");
    }

    private void fail(Task<?> task, String prefix) {
        bar.setProgress(0); buttons(false);
        Throwable ex = task.getException();
        resultStyle("danger");
        result.setText(prefix + ": " + (ex != null ? ex.getMessage() : "unknown error"));
    }

    private void buttons(boolean busy) {
        verify.setDisable(busy);
        verifyOnChain.setDisable(busy);
    }

    private void showResultDetails(boolean show) {
        onchainResult.setVisible(show);
        onchainResult.setManaged(show);
    }

    private void run(Task<?> task, String name) {
        var t = new Thread(task, name);
        t.setDaemon(true);
        t.start();
    }

    private void resultStyle(String cls) {
        result.getStyleClass().removeAll("success", "danger");
        if (cls != null) result.getStyleClass().add(cls);
    }

    private static Label fieldLabel(String text) {
        var l = new Label(text);
        l.getStyleClass().add("field-label");
        return l;
    }

    private static Label section(String text) {
        var l = new Label(text);
        l.getStyleClass().add("section-title");
        return l;
    }
}
