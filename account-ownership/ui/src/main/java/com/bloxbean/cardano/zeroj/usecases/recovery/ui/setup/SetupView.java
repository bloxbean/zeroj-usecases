package com.bloxbean.cardano.zeroj.usecases.recovery.ui.setup;

import com.bloxbean.cardano.zeroj.usecases.recovery.cli.Flows;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.nio.file.Path;

/**
 * The "Generate locally" screen: a single-party trusted setup on this machine (dev/testing only),
 * gated behind an explicit acknowledgement — mirroring the CLI's {@code --i-understand-insecure}.
 * The heavy setup (~5–6 min, ~8 GB heap) runs on a background {@link Task} so the UI stays
 * responsive; progress is indeterminate (the streamed setup doesn't emit a percentage) with stage
 * messages.
 */
public final class SetupView {

    /** Setup needs roughly this much heap; below it we warn (it will otherwise OOM). */
    private static final long MIN_HEAP_BYTES = 7L << 30;

    private final Path keysDir;
    private final Runnable onBack;

    private final CheckBox ack = new CheckBox("I understand this key is for testing only — this machine could forge proofs.");
    private final ProgressBar bar = new ProgressBar(0);
    private final Label status = new Label();
    private final Button generate = new Button("Generate keys");
    private Task<Path> task;

    public SetupView(Path keysDir, Runnable onBack) {
        this.keysDir = keysDir;
        this.onBack = onBack;
    }

    public Parent build() {
        var title = new Label("Generate keys locally (dev/testing)");
        title.getStyleClass().add("title");

        var warn = new Label("A single-party trusted setup runs entirely on this computer. It is "
                + "perfect for trying the tool, but the machine learns the setup randomness and could "
                + "forge proofs — never use a locally-generated key in production.");
        warn.setWrapText(true);
        warn.getStyleClass().add("warn");

        var dest = new Label("Bundle location: " + keysDir.resolve("keys").toAbsolutePath());
        dest.setWrapText(true);
        dest.getStyleClass().add("hint");

        long maxHeap = Runtime.getRuntime().maxMemory();
        var heap = new Label(maxHeap >= MIN_HEAP_BYTES
                ? "Available heap: " + human(maxHeap) + " — OK."
                : "Warning: available heap is only " + human(maxHeap) + "; setup needs ~8 GB and may "
                    + "run out of memory. Close other apps or run on a machine with more RAM.");
        heap.setWrapText(true);
        heap.getStyleClass().add(maxHeap >= MIN_HEAP_BYTES ? "ok-muted" : "danger");

        bar.setMaxWidth(Double.MAX_VALUE);
        status.setWrapText(true);
        status.getStyleClass().add("status");
        status.setText("Tick the box, then Generate. Takes about 5–6 minutes.");

        generate.setDisable(true);
        ack.selectedProperty().addListener((o, was, now) -> generate.setDisable(!now));
        generate.setOnAction(e -> startSetup());

        var back = new Button("Back");
        back.setOnAction(e -> { if (task != null) task.cancel(); onBack.run(); });
        back.getStyleClass().add("ghost");

        var buttons = new HBox(10, generate, back);

        var box = new VBox(12, title, warn, dest, heap, ack, bar, status, buttons);
        box.setAlignment(Pos.TOP_LEFT);
        return box;
    }

    private void startSetup() {
        final Path bundleDir = keysDir.resolve("keys");
        task = new Task<>() {
            @Override
            protected Path call() throws Exception {
                Flows.generateLocalKeys(bundleDir, this::updateMessage);
                return bundleDir;
            }
        };

        // setup emits no percentage — show an indeterminate bar while it runs
        bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        status.textProperty().bind(task.messageProperty());

        task.setOnSucceeded(e -> {
            finish();
            status.setText("Keys ready at " + task.getValue().toAbsolutePath() + ". You can now prove.");
        });
        task.setOnCancelled(e -> { finish(); status.setText("Cancelled."); });
        task.setOnFailed(e -> {
            finish();
            Throwable ex = task.getException();
            status.setText("Setup failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        generate.setDisable(true);
        ack.setDisable(true);
        var thread = new Thread(task, "local-setup");
        thread.setDaemon(true);
        thread.start();
    }

    private void finish() {
        status.textProperty().unbind();
        bar.setProgress(0);
        ack.setDisable(false);
        generate.setDisable(!ack.isSelected());
    }

    private static String human(long bytes) {
        double gb = bytes / (1024.0 * 1024 * 1024);
        return String.format("%.1f GB", gb);
    }
}
