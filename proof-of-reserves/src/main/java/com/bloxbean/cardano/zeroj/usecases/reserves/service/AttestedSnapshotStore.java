package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.usecases.reserves.config.DemoFiles;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * The last attested snapshot (its salts, salted ids and balances), persisted owner-only and
 * atomically in the demo data directory, so customers can still check the live attestation after
 * a restart. It holds every customer's salt, so it is as sensitive as the account database.
 *
 * <p>A file that is unreadable, malformed, for another tree depth, or whose leaves do not
 * reproduce its own root stops startup (fail closed); {@code ./demo.sh proof-of-reserves
 * --clean-cache} removes it with the rest of the deployment.
 */
final class AttestedSnapshotStore {

    static final String FILE = "attested-snapshot.json";
    private static final String VERSION = "zeroj.reserves.attested-snapshot.v1";
    private static final ObjectMapper JSON = new ObjectMapper();

    private AttestedSnapshotStore() {}

    static Path path(Path dataDir) {
        return dataDir.resolve(FILE);
    }

    static void write(Path dataDir, MerkleSumTreeService.Snapshot s, long period) throws IOException {
        ObjectNode root = JSON.createObjectNode();
        root.put("version", VERSION);
        root.put("period", period);
        root.put("treeDepth", s.treeDepth());
        root.put("root", s.root().toString());
        root.put("totalLiabilities", s.totalLiabilities().toString());
        ArrayNode ids = root.putArray("leafIds");
        ArrayNode balances = root.putArray("leafBalances");
        ArrayNode salts = root.putArray("salts");
        for (int i = 0; i < s.leafIds().length; i++) {
            ids.add(s.leafIds()[i].toString());
            balances.add(s.leafBalances()[i].toString());
            if (s.salts()[i] == null) salts.addNull();
            else salts.add(s.salts()[i].toString());
        }
        ObjectNode index = root.putObject("index");
        s.index().forEach(index::put);
        DemoFiles.writeAtomically(path(dataDir), JSON.writeValueAsString(root).getBytes(StandardCharsets.UTF_8));
    }

    /** The stored snapshot, or null if there is none; throws if it is present but unusable. */
    static MerkleSumTreeService.Snapshot read(Path dataDir, int expectedDepth) {
        Path file = path(dataDir);
        if (!Files.exists(file)) return null;
        try {
            JsonNode n = JSON.readTree(Files.readString(file, StandardCharsets.UTF_8));
            if (!VERSION.equals(n.path("version").asText())) throw new IllegalArgumentException("unknown version");
            int depth = n.get("treeDepth").asInt();
            if (depth != expectedDepth) throw new IllegalArgumentException("tree depth " + depth + " != " + expectedDepth);
            int size = 1 << depth;
            if (n.get("leafIds").size() != size || n.get("leafBalances").size() != size || n.get("salts").size() != size) {
                throw new IllegalArgumentException("wrong leaf count");
            }
            BigInteger[] ids = new BigInteger[size];
            BigInteger[] balances = new BigInteger[size];
            BigInteger[] salts = new BigInteger[size];
            BigInteger total = BigInteger.ZERO;
            for (int i = 0; i < size; i++) {
                ids[i] = new BigInteger(n.get("leafIds").get(i).asText());
                balances[i] = new BigInteger(n.get("leafBalances").get(i).asText());
                JsonNode salt = n.get("salts").get(i);
                salts[i] = salt.isNull() ? null : new BigInteger(salt.asText());
                total = total.add(balances[i]);
            }
            Map<String, Integer> index = new HashMap<>();
            for (var it = n.get("index").fields(); it.hasNext(); ) {
                var e = it.next();
                int i = e.getValue().asInt();
                if (i < 0 || i >= size || salts[i] == null || index.containsValue(i)
                        || !ReserveLeaves.saltedId(e.getKey(), salts[i]).equals(ids[i])) {
                    throw new IllegalArgumentException("leaf of " + e.getKey() + " does not match its salt");
                }
                index.put(e.getKey(), i);
            }
            var s = MerkleSumTreeService.Snapshot.of(depth, salts, ids, balances, index, total);
            if (!s.root().equals(new BigInteger(n.get("root").asText()))
                    || !total.equals(new BigInteger(n.get("totalLiabilities").asText()))) {
                throw new IllegalArgumentException("leaves do not reproduce the stored root");
            }
            return s;
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("The attested snapshot " + file + " is unreadable or inconsistent ("
                    + e.getMessage() + "). Reset with ./demo.sh proof-of-reserves --clean-cache.", e);
        }
    }
}
