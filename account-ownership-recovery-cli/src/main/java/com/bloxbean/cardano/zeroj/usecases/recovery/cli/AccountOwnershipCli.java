package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Account-Ownership Proof CLI (ADR-0001).
 *
 * <p>Prove — in zero knowledge — that you know the HD-wallet <b>root key</b> behind a Cardano
 * address (the circuit re-derives the full CIP-1852 path and checks it reaches the address's payment
 * key hash), and verify that proof off-chain or on-chain. The seed never leaves the process.</p>
 *
 * <pre>
 *   setup    one-time: produce the proving/verification key bundle (coordinator)
 *   prove    generate a proof from your mnemonic
 *   verify   check a proof off-chain (default) or on-chain
 *   info     inspect a key bundle
 * </pre>
 */
@Command(name = "account-ownership-recovery-cli", mixinStandardHelpOptions = true,
        versionProvider = AccountOwnershipCli.Version.class,
        description = "Zero-knowledge proof of Cardano account ownership by root-key knowledge.",
        subcommands = {SetupCommand.class, ProveCommand.class, VerifyCommand.class, InfoCommand.class})
public final class AccountOwnershipCli {

    public static void main(String[] args) {
        System.exit(new CommandLine(new AccountOwnershipCli())
                .setExecutionExceptionHandler((e, cmd, parse) -> {
                    cmd.getErr().println(cmd.getColorScheme().errorText("Error: " + e.getMessage()));
                    if (System.getenv("CLI_DEBUG") != null) e.printStackTrace(cmd.getErr());
                    return 1;
                })
                .execute(args));
    }

    static class Version implements CommandLine.IVersionProvider {
        @Override public String[] getVersion() {
            String v = AccountOwnershipCli.class.getPackage().getImplementationVersion();
            return new String[]{"account-ownership-recovery-cli " + (v != null ? v : "dev")};
        }
    }
}
