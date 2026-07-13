package com.bloxbean.cardano.zeroj.usecases.recovery.ui;

import javafx.scene.SnapshotParameters;
import javafx.scene.image.PixelReader;
import javafx.scene.image.WritableImage;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.testfx.framework.junit5.ApplicationTest;
import org.testfx.util.WaitForAsyncUtils;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Renders the styled UI to PNGs via the Monocle software pipeline (no display) so the look & feel
 * can be reviewed without launching the app. Gated: run with {@code -Dui.capture=true}.
 */
class CaptureTest extends ApplicationTest {

    @Override
    public void start(Stage stage) {
        new AccountOwnershipApp().start(stage);
    }

    @Test
    @EnabledIfSystemProperty(named = "ui.capture", matches = "true")
    void captureScreens() throws Exception {
        Path outDir = Path.of("build", "screenshots");
        Files.createDirectories(outDir);

        snap(outDir.resolve("1-home.png"));

        clickOn("Generate locally (dev/testing)");
        WaitForAsyncUtils.waitForFxEvents();
        snap(outDir.resolve("2-generate.png"));

        clickOn("Back");
        WaitForAsyncUtils.waitForFxEvents();
        clickOn("Download official keys");
        WaitForAsyncUtils.waitForFxEvents();
        snap(outDir.resolve("3-download.png"));
    }

    private void snap(Path file) throws Exception {
        var ref = new AtomicReference<WritableImage>();
        interact(() -> ref.set(listWindows().get(0).getScene().getRoot()
                .snapshot(new SnapshotParameters(), null)));
        WritableImage fx = ref.get();
        int w = (int) fx.getWidth(), h = (int) fx.getHeight();
        BufferedImage bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        PixelReader pr = fx.getPixelReader();
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++)
                bi.setRGB(x, y, pr.getArgb(x, y));
        ImageIO.write(bi, "png", file.toFile());
        System.out.println("[capture] wrote " + file.toAbsolutePath() + " (" + w + "x" + h + ")");
    }
}
