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
    private final TextField recipientField = new TextField();
    private final TextField accountField = new TextField("0");
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
        recipientField.setPromptText("recipient address (bech32) the refund goes to");
        accountField.setPrefColumnCount(4);
        roleField.setPrefColumnCount(4);
        indexField.setPrefColumnCount(6);

        var path = new HBox(8, fieldLabel("Account"), accountField,
                fieldLabel("Role"), roleField, fieldLabel("Index"), indexField);
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
                ? "The recipient is bound into the proof — the refund can only go there. The wallet "
                    + "path stays private; only the pkh and recipient are public."
                : "No key bundle found — download or generate keys first.");
        prove.setOnAction(e -> startProve());

        var back = new Button("Back");
        back.setOnAction(e -> { if (task != null) task.cancel(); onBack.run(); });
        back.getStyleClass().add("ghost");

        var buttons = new HBox(10, prove, verifyNow, back);

        var box = new VBox(12, title,
                fieldLabel("Mnemonic"), mnemonic,
                fieldLabel("Recipient address"), recipientField,
                path, mainnet, bar, status, buttons);
        box.setAlignment(Pos.TOP_LEFT);
        return box;
    }

    private static Label fieldLabel(String text) {
        var l = new Label(text);
        l.getStyleClass().add("field-label");
        return l;
    }

    private void startProve() {
        final int account, role, index;
        try {
            account = Integer.parseInt(accountField.getText().trim());
            role = Integer.parseInt(roleField.getText().trim());
            index = Integer.parseInt(indexField.getText().trim());
        } catch (NumberFormatException ex) {
            status.setText("Account, role and index must be whole numbers.");
            return;
        }
        if (account < 0 || role < 0 || index < 0) { status.setText("Account, role and index must be 0 or greater."); return; }

        final String recipient = recipientField.getText() == null ? "" : recipientField.getText().trim();
        if (recipient.isEmpty()) { status.setText("Enter the recipient address the refund should go to."); return; }

        String m = mnemonic.getText();
        if (m == null || m.isBlank()) { status.setText("Enter your wallet mnemonic."); return; }
        final char[] mnemonicChars = m.toCharArray();
        mnemonic.clear();
        final boolean net = mainnet.isSelected();

        task = new Task<>() {
            @Override
            protected Flows.ProveResult call() throws Exception {
                return Flows.prove(bundleDir, mnemonicChars, account, role, index, recipient, net, proofDir, this::updateMessage);
            }
        };
        bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        status.textProperty().bind(task.messageProperty());

        task.setOnSucceeded(e -> {
            finish();
            var r = task.getValue();
            status.setText("Proof generated and self-checked VALID.\n"
                    + "Address: " + r.address() + "\n"
                    + "Recipient: " + r.recipient() + "\n"
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
