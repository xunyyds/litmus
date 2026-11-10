package io.litmus.core;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * native 侧一次性快照的 Java 视图。见 docs/04-契约.md §4.5。
 *
 * <p>解析必须<b>容忍缺字段</b>：不同 ABI / 不同 ROM 上子对象可能整体缺失。
 */
public final class NativeSnapshot {

    public final boolean ok;
    public final String error;
    public final String abi;
    public final int pid;
    public final int tracerPid;
    public final long vdsoSize;

    /** 匿名可执行映射。 */
    public final int anonExecCount;
    public final long anonExecBytes;
    public final List<String> anonExecSamples;

    /** RWX 段。 */
    public final int rwxCount;
    public final List<String> rwxSamples;

    /** memfd 可执行。 */
    public final int memfdCount;
    public final List<String> memfdSamples;

    /** maps 里带 (deleted) 的 file-backed 段。 */
    public final int deletedCount;
    public final List<String> deletedSamples;

    /** 线程数与线程名。 */
    public final int threadCount;
    public final List<String> threadNames;

    /** inline hook 扫描：扫描了多少个函数入口，命中多少个。 */
    public final int inlineScanned;
    public final int inlineHits;
    public final List<String> inlineSamples;

    /** GOT/PLT 落点检查。 */
    public final int gotScanned;
    public final int gotBad;
    public final List<String> gotSamples;

    /** 系统调用耗时统计（ns）。 */
    public final int timingN;
    public final long timingMedianNs;
    public final long timingP99Ns;
    public final long timingJitterNs;

    private NativeSnapshot(JSONObject o) {
        ok = o.optBoolean("ok", false);
        error = o.optString("error", "");
        abi = o.optString("abi", "");
        pid = o.optInt("pid", -1);
        tracerPid = o.optInt("tracerPid", -1);
        vdsoSize = o.optLong("vdsoSize", 0L);

        JSONObject anon = o.optJSONObject("anonExec");
        anonExecCount = anon == null ? -1 : anon.optInt("count", -1);
        anonExecBytes = anon == null ? 0L : anon.optLong("bytes", 0L);
        anonExecSamples = readList(anon, "samples");

        JSONObject rwx = o.optJSONObject("rwx");
        rwxCount = rwx == null ? -1 : rwx.optInt("count", -1);
        rwxSamples = readList(rwx, "samples");

        JSONObject memfd = o.optJSONObject("memfd");
        memfdCount = memfd == null ? -1 : memfd.optInt("count", -1);
        memfdSamples = readList(memfd, "samples");

        JSONObject deleted = o.optJSONObject("deleted");
        deletedCount = deleted == null ? -1 : deleted.optInt("count", -1);
        deletedSamples = readList(deleted, "samples");

        JSONObject threads = o.optJSONObject("threads");
        threadCount = threads == null ? -1 : threads.optInt("count", -1);
        threadNames = readList(threads, "names");

        JSONObject ih = o.optJSONObject("inlineHook");
        inlineScanned = ih == null ? -1 : ih.optInt("scanned", -1);
        inlineHits = ih == null ? -1 : ih.optInt("hits", -1);
        inlineSamples = readList(ih, "samples");

        JSONObject got = o.optJSONObject("gotCheck");
        gotScanned = got == null ? -1 : got.optInt("scanned", -1);
        gotBad = got == null ? -1 : got.optInt("bad", -1);
        gotSamples = readList(got, "samples");

        JSONObject t = o.optJSONObject("timing");
        timingN = t == null ? 0 : t.optInt("n", 0);
        timingMedianNs = t == null ? 0L : t.optLong("medianNs", 0L);
        timingP99Ns = t == null ? 0L : t.optLong("p99Ns", 0L);
        timingJitterNs = t == null ? 0L : t.optLong("jitterNs", 0L);
    }

    public static NativeSnapshot parse(String json) {
        if (json == null || json.trim().isEmpty()) {
            return null;
        }
        try {
            return new NativeSnapshot(new JSONObject(json));
        } catch (Throwable t) {
            return null;
        }
    }

    private static List<String> readList(JSONObject o, String key) {
        List<String> out = new ArrayList<>();
        if (o == null) {
            return out;
        }
        JSONArray a = o.optJSONArray(key);
        if (a == null) {
            return out;
        }
        for (int i = 0; i < a.length() && out.size() < 32; i++) {
            String s = a.optString(i, "");
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }
}
