package com.bloxbean.cardano.zeroj.usecases.recovery.ui;

import com.bloxbean.cardano.zeroj.usecases.recovery.cli.Flows;
import com.bloxbean.cardano.zeroj.usecases.recovery.ui.download.DownloadView;
import com.bloxbean.cardano.zeroj.usecases.recovery.ui.prove.ProveView;
import com.bloxbean.cardano.zeroj.usecases.recovery.ui.setup.SetupView;
import com.bloxbean.cardano.zeroj.usecases.recovery.ui.verify.VerifyView;
import javafx.application.Application;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.InputStream;
import java.nio.file.Path;

/**
 * Desktop front-end for the account-ownership proof flow (ADR-0002). A thin JavaFX shell over the
 * {@code :cli} service layer (via {@link Flows}, whose Path/primitive signatures keep this module
 * free of ZeroJ crypto types): get a key bundle (download the official ceremony bundle or generate
 * a local dev bundle), then prove and verify. Everything is pure Java — no native library, so it
 * runs on every OS.
 */
public final class AccountOwnershipApp extends Application {

    private static final Path APP_DIR = Path.of(System.getProperty("user.home"), ".account-ownership");
    private static final Path KEYS_DIR = APP_DIR.resolve("keys");
    private static final Path PROOFS_DIR = APP_DIR.resolve("proofs");

    private Stage stage;
    private Image logo;

    @Override
    public void start(Stage stage) {
        this.stage = stage;
        this.logo = loadImage("/icons/logo-256.png");
        stage.setTitle("Account Ownership Proof");
        if (logo != null) stage.getIcons().add(logo);
        showHome();
        stage.show();
    }

    private void showHome() { setContent(home(), 620, 520); }

    private void showDownload() { setContent(new DownloadView(APP_DIR, this::showHome).build(), 660, 520); }

    private void showSetup() { setContent(new SetupView(APP_DIR, this::showHome).build(), 660, 560); }

    private void showProve() {
        setContent(new ProveView(KEYS_DIR, PROOFS_DIR, this::showHome, this::showVerify).build(), 660, 540);
    }

    private void showVerify(Path proofDir) {
        setContent(new VerifyView(KEYS_DIR, proofDir, this::showHome).build(), 660, 440);
    }

    /** Home: key/proof status + the actions available in the current state. */
    private VBox home() {
        var title = titled("Account Ownership Proof");

        boolean haveKeys = Flows.hasKeys(KEYS_DIR);
        String fp = haveKeys ? Flows.keyFingerprint(KEYS_DIR) : null;
        var keyStatus = new Label(haveKeys
                ? "✓ Keys ready" + (fp != null ? "   " + fp : "")
                : "No keys yet — download or generate them to begin.");
        keyStatus.getStyleClass().add(haveKeys ? "ok-muted" : "warn");

        var download = wide(new Button("Download official keys"), this::showDownload);
        var generate = wide(new Button("Generate locally (dev/testing)"), this::showSetup);
        generate.getStyleClass().add("secondary");

        var prove = wide(new Button("Prove ownership"), this::showProve);
        prove.setDisable(!haveKeys);
        var verify = wide(new Button("Verify a proof"), () -> showVerify(PROOFS_DIR));
        verify.setDisable(!haveKeys);
        verify.getStyleClass().add("secondary");

        var box = new VBox(12, title, keyStatus,
                section("1. Get proving keys"), download, generate,
                new Separator(),
                section("2. Prove & verify"), prove, verify);
        return box;
    }

    // ---- frame ----

    private void setContent(Parent screen, double w, double h) {
        var card = new VBox(screen);
        card.getStyleClass().add("content");
        VBox.setVgrow(screen, Priority.ALWAYS);
        var wrap = new VBox(card);
        wrap.getStyleClass().add("screen-wrap");
        VBox.setVgrow(card, Priority.ALWAYS);

        var frame = new BorderPane();
        frame.setTop(header());
        frame.setCenter(wrap);

        if (stage.getScene() == null) {
            var scene = new Scene(frame, w, h);
            var css = getClass().getResource("/styles.css");
            if (css != null) scene.getStylesheets().add(css.toExternalForm());
            stage.setScene(scene);
        } else {
            stage.getScene().setRoot(frame);
        }
        stage.setWidth(w);
        stage.setHeight(h);
    }

    private Node header() {
        var name = new Label("Account Ownership Proof");
        name.getStyleClass().add("app-name");
        var bar = new HBox(name);
        if (logo != null) {
            var iv = new ImageView(logo);
            iv.setFitWidth(30); iv.setFitHeight(30);
            iv.setPreserveRatio(true); iv.setSmooth(true);
            bar.getChildren().add(0, iv);
        }
        bar.getStyleClass().add("app-header");
        return bar;
    }

    private static Label titled(String text) {
        var l = new Label(text);
        l.getStyleClass().add("title");
        return l;
    }

    private static Label section(String text) {
        var l = new Label(text);
        l.getStyleClass().add("section-title");
        return l;
    }

    private static Button wide(Button b, Runnable action) {
        b.setMaxWidth(Double.MAX_VALUE);
        b.setOnAction(e -> action.run());
        return b;
    }

    private Image loadImage(String resource) {
        try (InputStream in = getClass().getResourceAsStream(resource)) {
            return in != null ? new Image(in) : null;
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
