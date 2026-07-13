package com.bloxbean.cardano.zeroj.usecases.recovery.ui.verify;

import com.bloxbean.cardano.zeroj.usecases.recovery.cli.Flows;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.nio.file.Path;

/**
 * The "Verify" screen: off-chain verification of the generated proof against the key bundle — the
 * pure-Java pairing check, sub-second, on a background {@link Task}. On-chain verification
 * (Yaci DevKit / Blockfrost) is a later milestone.
 */
public final class VerifyView {

    private final Path bundleDir;
    private final Path proofDir;
    private final Runnable onBack;

    private final ProgressBar bar = new ProgressBar(0);
    private final Label result = new Label();
    private final Button verify = new Button("Verify off-chain");
    private Task<Boolean> task;

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

        boolean haveProof = Flows.hasProof(proofDir);
        boolean haveKeys = Flows.hasKeys(bundleDir);
        verify.setDisable(!(haveProof && haveKeys));
        result.setText(!haveKeys ? "No key bundle found — download or generate keys first."
                : !haveProof ? "No proof found — generate one on the Prove screen first."
                : "Ready to verify.");
        verify.setOnAction(e -> startVerify());

        var onchain = new Button("Verify on-chain (coming soon)");
        onchain.setDisable(true);
        onchain.getStyleClass().add("secondary");

        var back = new Button("Back");
        back.setOnAction(e -> onBack.run());
        back.getStyleClass().add("ghost");

        var buttons = new HBox(10, verify, onchain, back);

        var box = new VBox(12, title, info, bar, result, buttons);
        box.setAlignment(Pos.TOP_LEFT);
        return box;
    }

    private void resultStyle(String cls) {
        result.getStyleClass().removeAll("success", "danger");
        if (cls != null) result.getStyleClass().add(cls);
    }

    private void startVerify() {
        task = new Task<>() {
            @Override
            protected Boolean call() throws Exception {
                return Flows.verifyOffChain(bundleDir, proofDir);
            }
        };
        bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        result.setText("Verifying…");
        verify.setDisable(true);

        task.setOnSucceeded(e -> {
            bar.setProgress(0);
            verify.setDisable(false);
            boolean ok = Boolean.TRUE.equals(task.getValue());
            result.setText(ok ? "✓ VALID — the proof verifies against this key bundle."
                              : "✗ INVALID — the proof did not verify.");
            resultStyle(ok ? "success" : "danger");
        });
        task.setOnFailed(e -> {
            bar.setProgress(0);
            verify.setDisable(false);
            Throwable ex = task.getException();
            resultStyle("danger");
            result.setText("Verification error: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        var thread = new Thread(task, "verify");
        thread.setDaemon(true);
        thread.start();
    }
}
