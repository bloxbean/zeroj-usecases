package com.bloxbean.cardano.zeroj.usecases.recovery.ui.download;

import com.bloxbean.cardano.zeroj.usecases.recovery.cli.Flows;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The "Download official keys" screen: a URL (+ optional SHA-256) → a resumable transfer with a
 * live progress bar, throughput, and cancel. Wraps {@link ResumableDownloader} in a JavaFX
 * {@link Task} so progress binds straight to the UI and cancellation is cooperative (the partial
 * {@code .part} file is kept, so pressing Start again resumes).
 *
 * <p>Extraction into the key bundle and circuit-fingerprint verification are the next milestone;
 * this screen currently downloads and integrity-checks the archive.</p>
 */
public final class DownloadView {

    private final Path targetDir;
    private final Runnable onBack;

    private final TextField urlField = new TextField();
    private final TextField shaField = new TextField();
    private final ProgressBar bar = new ProgressBar(0);
    private final Label status = new Label("Paste the bundle URL from the coordinator, then Start.");
    private final Button start = new Button("Start download");
    private final Button cancel = new Button("Cancel");
    private Task<Path> task;

    public DownloadView(Path targetDir, Runnable onBack) {
        this.targetDir = targetDir;
        this.onBack = onBack;
    }

    public Parent build() {
        var title = new Label("Download official keys");
        title.getStyleClass().add("title");

        urlField.setPromptText("https://…/account-ownership-keys.zip");
        shaField.setPromptText("expected SHA-256 (optional but recommended)");
        bar.setMaxWidth(Double.MAX_VALUE);
        status.setWrapText(true);
        status.getStyleClass().add("status");
        cancel.setDisable(true);

        start.setOnAction(e -> startDownload());
        cancel.setOnAction(e -> { if (task != null) task.cancel(); });
        cancel.getStyleClass().add("secondary");

        var back = new Button("Back");
        back.setOnAction(e -> { if (task != null) task.cancel(); onBack.run(); });
        back.getStyleClass().add("ghost");

        var buttons = new HBox(10, start, cancel, back);
        HBox.setHgrow(urlField, Priority.ALWAYS);

        var box = new VBox(12, title, fieldLabel("Bundle URL"), urlField,
                fieldLabel("SHA-256"), shaField, bar, status, buttons);
        box.setAlignment(Pos.TOP_LEFT);
        return box;
    }

    private static Label fieldLabel(String text) {
        var l = new Label(text);
        l.getStyleClass().add("field-label");
        return l;
    }

    private void startDownload() {
        final URI url;
        try {
            String raw = urlField.getText() == null ? "" : urlField.getText().trim();
            if (raw.isEmpty()) { status.setText("Enter a bundle URL first."); return; }
            url = URI.create(raw);
        } catch (RuntimeException ex) {
            status.setText("That doesn't look like a valid URL.");
            return;
        }
        final String sha = shaField.getText() == null || shaField.getText().isBlank() ? null : shaField.getText().trim();
        final Path dest = targetDir.resolve("account-ownership-keys.zip");

        final Path keysDir = targetDir.resolve("keys");
        task = new Task<>() {
            @Override
            protected Path call() throws Exception {
                var downloader = new ResumableDownloader();
                final long t0 = System.nanoTime();
                downloader.download(url, dest, sha, (done, total) -> {
                    if (total > 0) updateProgress(done, total);
                    double secs = (System.nanoTime() - t0) / 1e9;
                    double mbps = secs > 0 ? (done / 1_048_576.0) / secs : 0;
                    updateMessage(ResumableDownloader.human(done)
                            + (total > 0 ? " / " + ResumableDownloader.human(total) : "")
                            + String.format("   (%.1f MB/s)", mbps));
                }, this::isCancelled);
                // download done — extract + validate (indeterminate bar)
                updateProgress(-1, 1);
                Flows.extractBundle(dest, keysDir, this::updateMessage);
                Files.deleteIfExists(dest); // reclaim the archive's disk (~9.6 GB)
                return keysDir;
            }
        };

        bar.progressProperty().bind(task.progressProperty());
        status.textProperty().bind(task.messageProperty());

        task.setOnSucceeded(e -> {
            unbind();
            String fp = Flows.keyFingerprint(keysDir);
            status.setText("Keys ready" + (fp != null ? " (fingerprint " + fp + ")" : "")
                    + ". You can now prove.");
            toggle(false);
        });
        task.setOnCancelled(e -> {
            unbind();
            status.setText("Cancelled. The partial file is kept — Start again to resume.");
            toggle(false);
        });
        task.setOnFailed(e -> {
            unbind();
            Throwable ex = task.getException();
            status.setText("Download failed: " + (ex != null ? ex.getMessage() : "unknown error"));
            toggle(false);
        });

        toggle(true);
        var thread = new Thread(task, "key-download");
        thread.setDaemon(true);
        thread.start();
    }

    private void toggle(boolean downloading) {
        start.setDisable(downloading);
        cancel.setDisable(!downloading);
    }

    private void unbind() {
        bar.progressProperty().unbind();
        status.textProperty().unbind();
    }
}
