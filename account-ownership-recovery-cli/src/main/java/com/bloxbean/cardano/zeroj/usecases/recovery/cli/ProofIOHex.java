package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

/** Minimal hex codec shared by the proof/VK serializers. */
final class ProofIOHex {

    private ProofIOHex() {}

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return sb.toString();
    }

    static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) ((Character.digit(s.charAt(i * 2), 16) << 4) | Character.digit(s.charAt(i * 2 + 1), 16));
        return out;
    }
}
