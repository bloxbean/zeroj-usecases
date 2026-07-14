package com.bloxbean.cardano.zeroj.usecases.recovery.ui;

import javafx.application.Application;

/**
 * Fat-jar / jpackage entry point. When JavaFX is on the classpath (not the module path), launching
 * through a class that extends {@link Application} trips the "JavaFX runtime components are missing"
 * guard — so the packaged app starts here, in a plain class, and delegates to
 * {@link AccountOwnershipApp}.
 */
public final class Launcher {

    private Launcher() {}

    public static void main(String[] args) {
        Application.launch(AccountOwnershipApp.class, args);
    }
}
