package com.bloxbean.cardano.zeroj.usecases.recovery.ui;

import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;
import org.testfx.framework.junit5.ApplicationTest;
import org.testfx.util.WaitForAsyncUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless UI tests (TestFX + Monocle — no display) driving the real JavaFX app: the home screen's
 * navigation and a couple of screens' validation/enablement logic. These exercise the UI wiring
 * without the heavy crypto (which {@code FlowsE2ETest} covers).
 */
class AppUiTest extends ApplicationTest {

    @Override
    public void start(Stage stage) {
        new AccountOwnershipApp().start(stage);
    }

    @Test
    void home_showsKeySourceActions() {
        assertNotNull(lookup("Download official keys").tryQuery().orElse(null), "download action present");
        assertNotNull(lookup("Generate locally (dev/testing)").tryQuery().orElse(null), "generate action present");
        assertNotNull(lookup("Prove ownership").tryQuery().orElse(null), "prove action present");
        assertNotNull(lookup("Verify a proof").tryQuery().orElse(null), "verify action present");
    }

    @Test
    void generateScreen_ackCheckboxGatesTheButton() {
        clickOn("Generate locally (dev/testing)");
        WaitForAsyncUtils.waitForFxEvents();

        Button generate = lookup("Generate keys").queryButton();
        assertTrue(generate.isDisabled(), "Generate is disabled until the risk is acknowledged");

        clickOn(lookup(".check-box").queryAs(CheckBox.class));
        WaitForAsyncUtils.waitForFxEvents();
        assertFalse(generate.isDisabled(), "Generate enabled once acknowledged");
    }

    @Test
    void downloadScreen_hasUrlFieldAndStart() {
        clickOn("Download official keys");
        WaitForAsyncUtils.waitForFxEvents();

        assertNotNull(lookup("Start download").tryQuery().orElse(null), "Start button present");
        assertFalse(lookup(".text-field").queryAll().isEmpty(), "URL field present");

        // Start with an empty URL must report an error, not crash
        clickOn("Start download");
        WaitForAsyncUtils.waitForFxEvents();
        assertNotNull(lookup("Enter a bundle URL first.").tryQuery().orElse(null), "empty-URL is validated");
    }
}
