package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.vm.EvalOptions;
import org.julclang.vm.EvalResult;
import org.julclang.vm.JulcVm;
import org.julclang.vm.trace.ExecutionTraceEntry;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Opt-in cost profile of a validator evaluation ({@code ZEROJ_PROFILE=true}): re-runs the context
 * with Julc's source-mapped execution tracing and prints the CPU and memory spent per line of the
 * validator. Library code without a source map (ZeroJ's Groth16 verifier, Julc's stdlib) is
 * reported as one "untraced" remainder. Used to find where a transaction's fee goes.
 */
public final class CostProfiler {

    private CostProfiler() {}

    public static boolean enabled() {
        return "true".equalsIgnoreCase(System.getenv("ZEROJ_PROFILE"));
    }

    public static void profile(String label, Program program, CompileResult compiled, PlutusData context) {
        if (!enabled()) return;
        EvalResult result = JulcVm.create().evaluateWithArgs(program, compiled.target().ledgerTarget(), List.of(context),
                null, EvalOptions.DEFAULT.withSourceMap(compiled.sourceMap()).withTracing(true));
        long cpu = result.budgetConsumed().cpuSteps();
        long mem = result.budgetConsumed().memoryUnits();
        Map<String, long[]> lines = new LinkedHashMap<>();
        for (ExecutionTraceEntry e : result.executionTrace()) {
            long[] acc = lines.computeIfAbsent(e.fileName() + ":" + e.line(), k -> new long[3]);
            acc[0] += e.cpuDelta();
            acc[1] += e.memDelta();
            acc[2]++;
        }
        long tracedCpu = lines.values().stream().mapToLong(a -> a[0]).sum();
        long tracedMem = lines.values().stream().mapToLong(a -> a[1]).sum();
        var out = new StringBuilder();
        out.append(String.format("[profile %s] success=%s cpu=%,d mem=%,d; untraced (libraries) cpu=%,d (%.0f%%) mem=%,d (%.0f%%)%n",
                label, result.isSuccess(), cpu, mem, cpu - tracedCpu, 100.0 * (cpu - tracedCpu) / cpu,
                mem - tracedMem, 100.0 * (mem - tracedMem) / mem));
        appendTop(out, "cpu", lines, 0, cpu);
        appendTop(out, "mem", lines, 1, mem);
        System.out.print(out);
    }

    private static void appendTop(StringBuilder out, String what, Map<String, long[]> lines, int index, long total) {
        lines.entrySet().stream()
                .sorted(Comparator.comparingLong((Map.Entry<String, long[]> e) -> e.getValue()[index]).reversed())
                .limit(10)
                .forEach(e -> out.append(String.format("    top %s  %-34s %,15d (%4.1f%%) visits=%d%n", what, e.getKey(),
                        e.getValue()[index], 100.0 * e.getValue()[index] / total, e.getValue()[2])));
    }
}
