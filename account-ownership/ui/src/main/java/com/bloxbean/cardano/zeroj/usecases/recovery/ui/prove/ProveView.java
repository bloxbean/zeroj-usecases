package com.bloxbean.cardano.zeroj.usecases.recovery.ui.prove;

import com.bloxbean.cardano.zeroj.usecases.recovery.cli.Flows;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * The "Prove" screen: enter the wallet mnemonic (hidden) and the {@code role}/{@code index} of the
 * address to attest, then generate + self-check the proof against the local key bundle. Pure Java,
 * ~1–1.5 min, on a background {@link Task}. The mnemonic is read into a {@code char[]}, handed to
 * {@link Flows#prove} (which zeroes it), and the field is cleared immediately.
 */
public final class ProveView {

    private final Path bundleDir;
    private final Path proofDir;
    private final Runnable onBack;
    private final Consumer<Path> onProved;

    private final PasswordField mnemonic = new PasswordField();
    private final TextField roleField = new TextField("0");
    private final TextField indexField = new TextField("0");
    private final CheckBox mainnet = new CheckBox("Mainnet address (default: testnet)");
    private final ProgressBar bar = new ProgressBar(0);
    private final Label status = new Label();
    private final Button prove = new Button("Generate proof");
    private final Button verifyNow = new Button("Verify now");
    private Task<Flows.ProveResult> task;

    public ProveView(Path bundleDir, Path proofDir, Runnable onBack, Consumer<Path> onProved) {
        this.bundleDir = bundleDir;
        this.proofDir = proofDir;
        this.onBack = onBack;
        this.onProved = onProved;
    }

    public Parent build() {
        var title = new Label("Generate an ownership proof");
        title.getStyleClass().add("title");

        mnemonic.setPromptText("wallet mnemonic (hidden, never stored or sent)");
        roleField.setPrefColumnCount(4);
        indexField.setPrefColumnCount(6);

        var path = new HBox(8, fieldLabel("Role"), roleField, fieldLabel("Index"), indexField);
        path.setAlignment(Pos.CENTER_LEFT);

        bar.setMaxWidth(Double.MAX_VALUE);
        status.setWrapText(true);
        status.getStyleClass().add("status");
        verifyNow.setDisable(true);
        verifyNow.setOnAction(e -> onProved.accept(proofDir));
        verifyNow.getStyleClass().add("secondary");

        boolean haveKeys = Flows.hasKeys(bundleDir);
        prove.setDisable(!haveKeys);
        status.setText(haveKeys
                ? "role 0 = external payment address, 1 = change. The path stays private — only the "
                    + "payment key hash is public."
                : "No key bundle found — download or generate keys first.");
        prove.setOnAction(e -> startProve());

        var back = new Button("Back");
        back.setOnAction(e -> { if (task != null) task.cancel(); onBack.run(); });
        back.getStyleClass().add("ghost");

        var buttons = new HBox(10, prove, verifyNow, back);

        var box = new VBox(12, title, fieldLabel("Mnemonic"), mnemonic, path, mainnet, bar, status, buttons);
        box.setAlignment(Pos.TOP_LEFT);
        return box;
    }

    private static Label fieldLabel(String text) {
        var l = new Label(text);
        l.getStyleClass().add("field-label");
        return l;
    }

    private void startProve() {
        final int role, index;
        try {
            role = Integer.parseInt(roleField.getText().trim());
            index = Integer.parseInt(indexField.getText().trim());
        } catch (NumberFormatException ex) {
            status.setText("Role and index must be whole numbers.");
            return;
        }
        if (role < 0 || index < 0) { status.setText("Role and index must be 0 or greater."); return; }

        String m = mnemonic.getText();
        if (m == null || m.isBlank()) { status.setText("Enter your wallet mnemonic."); return; }
        final char[] mnemonicChars = m.toCharArray();
        mnemonic.clear();
        final boolean net = mainnet.isSelected();

        task = new Task<>() {
            @Override
            protected Flows.ProveResult call() throws Exception {
                return Flows.prove(bundleDir, mnemonicChars, 0, role, index, net, proofDir, this::updateMessage);
            }
        };
        bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        status.textProperty().bind(task.messageProperty());

        task.setOnSucceeded(e -> {
            finish();
            var r = task.getValue();
            status.setText("Proof generated and self-checked VALID.\n"
                    + "Address: " + r.address() + "\n"
                    + "Payment key hash: " + r.pkhHex() + "\n"
                    + "Saved to: " + r.proofDir().toAbsolutePath());
            verifyNow.setDisable(false);
        });
        task.setOnCancelled(e -> { finish(); status.setText("Cancelled."); });
        task.setOnFailed(e -> {
            finish();
            Throwable ex = task.getException();
            status.setText("Prove failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        prove.setDisable(true);
        var thread = new Thread(task, "prove");
        thread.setDaemon(true);
        thread.start();
    }

    private void finish() {
        status.textProperty().unbind();
        bar.setProgress(0);
        prove.setDisable(false);
    }
}
