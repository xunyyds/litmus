package io.litmus.canary;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import io.litmus.core.LitmusRunner;

/**
 * 历史报告的文件视图。
 *
 * <p>数据源就是 {@code getExternalFilesDir(null)/litmus/report-*.json} —— 即
 * {@link LitmusRunner#publish} 每次跑完落的盘。**不新建索引文件**：
 * 索引与真实文件一旦不同步（删除/被清理/被 adb pull 走），UI 就会撒谎；
 * 直接按 mtime 倒序扫目录最诚实，代价只是一次最多读 10 个 11KB 的 JSON。
 */
final class ReportStore {

    private static final String TAG = "LitmusReportStore";

    /** 磁盘上最多扫描多少个文件（避免用户手动塞了几百个之后拖慢首帧）。 */
    static final int MAX_SCAN = 10;
    /** Hero 下面那行历史只显示最近 5 次。 */
    static final int MAX_SHOW = 5;

    /** 一条历史：只要 UI 需要的三个数（分数 / 时间 / runId），不常驻整份 JSON。 */
    static final class Item {
        final File file;
        final String runId;
        final long mtime;
        final boolean scored;
        final double score;

        Item(File file, String runId, long mtime, boolean scored, double score) {
            this.file = file;
            this.runId = runId;
            this.mtime = mtime;
            this.scored = scored;
            this.score = score;
        }
    }

    private ReportStore() {
    }

    /** 按 mtime 倒序返回（最多 {@link #MAX_SCAN} 条）。失败的文件直接跳过，不让 UI 崩。 */
    static List<Item> list(Context c) {
        List<Item> out = new ArrayList<>();
        File dir;
        try {
            dir = LitmusRunner.outputDir(c);
        } catch (Throwable t) {
            return out;
        }
        File[] files = dir.listFiles((d, name) -> name.startsWith("report-") && name.endsWith(".json"));
        if (files == null || files.length == 0) {
            return out;
        }
        List<File> sorted = new ArrayList<>();
        Collections.addAll(sorted, files);
        sorted.sort(Comparator.comparingLong(File::lastModified).reversed());
        for (int i = 0; i < sorted.size() && i < MAX_SCAN; i++) {
            File f = sorted.get(i);
            Item item = probe(f);
            if (item != null) {
                out.add(item);
            }
        }
        return out;
    }

    /** 只解析三个字段；解析不了就当「无分历史」（仍可点开看，只是不在历史条上显示数字）。 */
    private static Item probe(File f) {
        try {
            JSONObject report = read(f);
            JSONObject run = report.optJSONObject("run");
            JSONObject summary = report.optJSONObject("summary");
            String runId = run == null ? stripId(f) : run.optString("id", stripId(f));
            Object raw = summary == null ? null : summary.opt("score");
            boolean scored = raw instanceof Number;
            double score = scored ? ((Number) raw).doubleValue() : Double.NaN;
            return new Item(f, runId, f.lastModified(), scored, score);
        } catch (Throwable t) {
            Log.w(TAG, "skip unreadable report: " + f.getName() + " (" + t + ")");
            return null;
        }
    }

    static JSONObject read(File f) throws Exception {
        byte[] bytes = readFully(f);
        return new JSONObject(new String(bytes, StandardCharsets.UTF_8));
    }

    private static byte[] readFully(File f) throws Exception {
        FileInputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream((int) Math.max(1024, f.length()));
            byte[] buf = new byte[16 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        } finally {
            in.close();
        }
    }

    static boolean delete(File f) {
        boolean ok = f != null && f.exists() && f.delete();
        if (!ok) {
            Log.w(TAG, "delete failed: " + f);
        }
        return ok;
    }

    private static String stripId(File f) {
        String name = f.getName();
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot).replace("report-", "") : name;
    }

    // ------------------------------------------------------------------ 时间

    /** 相对时间：刚刚 / N 分钟前 / N 小时前 / 昨天 / N 天前。 */
    static String relTime(long now, long then) {
        long d = Math.max(0L, now - then) / 1000L;
        if (d < 60) {
            return "刚刚";
        }
        if (d < 3600) {
            return (d / 60) + " 分钟前";
        }
        if (d < 86400) {
            return (d / 3600) + " 小时前";
        }
        if (d < 86400L * 2) {
            return "昨天";
        }
        if (d < 86400L * 30) {
            return (d / 86400) + " 天前";
        }
        return (d / (86400L * 30)) + " 个月前";
    }
}
