package io.litmus.core;

import android.content.Context;
import android.os.Build;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

/**
 * 一次检测运行：采样 → 跑全部向量 → 组装 report → 落盘 + logcat。
 *
 * <p>契约见 docs/04-契约.md §4.1 / §4.3。**不能**在主线程跑（native 采样约 5~30ms，
 * 向量合计 < 200ms，但 rt.timing 自带 200 次采样，放后台线程更稳）。
 */
public final class LitmusRunner {

    public static final String TAG = "LitmusReport";
    public static final String PREFIX = "LITMUS_REPORT ";
    public static final String CHUNK_PREFIX = "LITMUS_REPORT_CHUNK ";
    public static final String PATH_PREFIX = "LITMUS_REPORT_PATH ";
    /** logcat 单行安全上限（契约 §4.3：4000 字节）。 */
    private static final int LOGCAT_LIMIT = 3800;

    private LitmusRunner() {
    }

    public static File outputDir(Context c) {
        File base = c.getExternalFilesDir(null);
        if (base == null) {
            base = c.getFilesDir();
        }
        File dir = new File(base, "litmus");
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        return dir;
    }

    public static JSONObject run(Context c) {
        final long t0 = SystemClock.elapsedRealtime();
        final String runId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        BuildInfo.init(c);

        AppSnapshot snap = null;
        String snapError = "";
        try {
            snap = AppSnapshot.capture(c);
        } catch (Throwable t) {
            snapError = t.getClass().getSimpleName() + ": " + t.getMessage();
            Log.w(TAG, "AppSnapshot failed: " + snapError);
        }

        NativeSnapshot nat = null;
        try {
            nat = NativeSnapshot.parse(NativeBridge.snapshot());
        } catch (Throwable t) {
            Log.w(TAG, "native snapshot unavailable: " + t);
        }

        Facts facts = new Facts();
        if (snap != null) {
            facts.put("apk.sha256", snap.apkSha256)
                    .put("apk.codePath", snap.codePath)
                    .put("apk.zip.fingerprint", snap.zipFingerprint)
                    .put("apk.dex.count", snap.dexCount)
                    .put("apk.dex.bytes", snap.dexBytes)
                    .put("cert.install", snap.installCerts)
                    .put("cert.signing", snap.signingCerts)
                    .put("cert.history", snap.certHistory)
                    .put("apk.multipleSigners", snap.multipleSigners)
                    .put("apk.installer", snap.installer)
                    .put("app.componentFactory", snap.appComponentFactory)
                    .put("app.class", snap.appClass)
                    .put("app.debuggable", snap.debuggable)
                    .put("app.targetSdk", snap.targetSdk);
        }
        if (nat != null) {
            facts.put("native.abi", nat.abi)
                    .put("native.pid", nat.pid)
                    .put("native.tracerPid", nat.tracerPid)
                    .put("native.threadCount", nat.threadCount)
                    .put("native.anonExecCount", nat.anonExecCount)
                    .put("native.rwxCount", nat.rwxCount)
                    .put("native.memfdCount", nat.memfdCount)
                    .put("native.deletedCount", nat.deletedCount)
                    .put("native.inlineHits", nat.inlineHits)
                    .put("native.gotBad", nat.gotBad);
        }

        LitmusContext ctx = new LitmusContext(c, snap, nat, facts);
        JSONArray signals = new JSONArray();

        List<Probe> probes = ProbeRegistry.all();
        for (Probe p : probes) {
            final long ps = SystemClock.elapsedRealtime();
            final JSONObject[] holder = new JSONObject[1];
            Probe.Sink sink = new Probe.Sink() {
                @Override
                public void emit(String verdict, double confidence, String evidence) {
                    if (holder[0] != null) {
                        return;  // 契约：一个 Probe 只 emit 一次
                    }
                    JSONObject s = new JSONObject();
                    try {
                        s.put("id", p.id());
                        s.put("category", p.category());
                        s.put("verdict", verdict);
                        s.put("confidence", Math.round(confidence * 1000d) / 1000d);
                        s.put("weight", p.weight());
                        s.put("tier", p.tier());
                        s.put("evidence", evidence == null ? "" : evidence);
                        s.put("ms", SystemClock.elapsedRealtime() - ps);
                    } catch (Throwable ignored) {
                    }
                    holder[0] = s;
                }
            };
            try {
                p.run(ctx, sink);
            } catch (Throwable t) {
                if (holder[0] == null) {
                    sink.error("probe threw " + t.getClass().getSimpleName() + ": " + t.getMessage());
                }
            }
            if (holder[0] == null) {
                sink.unknown("probe emitted nothing");
            }
            signals.put(holder[0]);
        }

        JSONObject summary = Score.summarize(signals);

        JSONObject report = new JSONObject();
        try {
            report.put("schema", "litmus.report/1");

            JSONObject producer = new JSONObject();
            producer.put("name", "io.litmus.canary");
            producer.put("version", BuildInfo.version);
            producer.put("flavor", BuildInfo.flavor);
            producer.put("buildUtc", BuildInfo.buildUtc);
            producer.put("kitId", BuildInfo.kitId);
            producer.put("hasNative", nat != null && nat.ok);
            report.put("producer", producer);

            JSONObject run = new JSONObject();
            run.put("id", runId);
            run.put("collectedAt", iso8601());
            run.put("durationMs", SystemClock.elapsedRealtime() - t0);
            run.put("passes", 1);
            run.put("probeCount", probes.size());
            run.put("snapshotError", snapError);
            report.put("run", run);

            report.put("app", appJson(c, snap));
            report.put("device", deviceJson());
            report.put("facts", facts.toJson());
            report.put("signals", signals);
            report.put("summary", summary);
        } catch (Throwable t) {
            Log.e(TAG, "assemble report failed", t);
        }
        return report;
    }

    /** 落盘 + logcat。返回写出的文件（可能为 null）。 */
    public static File publish(Context c, JSONObject report) {
        String json = report.toString();
        File out = null;
        try {
            String runId = report.optJSONObject("run") == null ? "unknown"
                    : report.optJSONObject("run").optString("id", "unknown");
            out = new File(outputDir(c), "report-" + runId + ".json");
            FileOutputStream fos = new FileOutputStream(out);
            try {
                fos.write(json.getBytes(StandardCharsets.UTF_8));
            } finally {
                fos.close();
            }
            Log.i(TAG, PATH_PREFIX + out.getAbsolutePath());
        } catch (Throwable t) {
            Log.w(TAG, "write report failed: " + t);
        }

        byte[] utf8 = json.getBytes(StandardCharsets.UTF_8);
        if (utf8.length <= LOGCAT_LIMIT) {
            Log.i(TAG, PREFIX + json);
        } else {
            String b64 = Base64.encodeToString(utf8, Base64.NO_WRAP);
            int chunk = 2800;
            int total = (b64.length() + chunk - 1) / chunk;
            for (int i = 0; i < total; i++) {
                int from = i * chunk;
                int to = Math.min(b64.length(), from + chunk);
                Log.i(TAG, CHUNK_PREFIX + (i + 1) + "/" + total + " " + b64.substring(from, to));
            }
        }
        return out;
    }

    private static JSONObject appJson(Context c, AppSnapshot snap) {
        JSONObject o = new JSONObject();
        try {
            o.put("package", c.getPackageName());
            o.put("pid", android.os.Process.myPid());
            o.put("uid", android.os.Process.myUid());
            o.put("process", snap == null ? "" : snap.processName);
            o.put("codePath", snap == null ? "" : snap.codePath);
            o.put("debuggable", snap != null && snap.debuggable);
            o.put("targetSdk", snap == null ? 0 : snap.targetSdk);
        } catch (Throwable ignored) {
        }
        return o;
    }

    private static JSONObject deviceJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("manufacturer", Build.MANUFACTURER);
            o.put("model", Build.MODEL);
            o.put("brand", Build.BRAND);
            o.put("fingerprint", Build.FINGERPRINT);
            o.put("sdk", Build.VERSION.SDK_INT);
            o.put("release", Build.VERSION.RELEASE);
            JSONArray abis = new JSONArray();
            if (Build.SUPPORTED_ABIS != null) {
                for (String a : Build.SUPPORTED_ABIS) {
                    abis.put(a);
                }
            }
            o.put("abis", abis);
        } catch (Throwable ignored) {
        }
        return o;
    }

    private static String iso8601() {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }
}
