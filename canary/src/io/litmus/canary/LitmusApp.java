package io.litmus.canary;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;

import io.litmus.core.LitmusRunner;
import io.litmus.core.BuildInfo;

/**
 * 靶包 Application：只干两件事。
 *
 * <ol>
 *   <li>初始化 {@link BuildInfo}（把构建期烘进 assets 的期望证书 SHA-256 读进来）；</li>
 *   <li>起一个后台线程跑 {@link LitmusRunner#run} + {@link LitmusRunner#publish}，
 *       结果放进静态字段给 {@link MainActivity} 取。</li>
 * </ol>
 *
 * <p><b>关键坑</b>：{@code onCreate} 在主线程，绝对不能在这里同步跑检测。
 * {@code AppSnapshot.capture()} 会把整个 APK 读一遍算 SHA-256（几十 MB 的包要几百 ms），
 * 再叠上 native 采样，必然触发 ANR（Input dispatching timed out, 5s）。所以这里只
 * {@code new Thread(...).start()} 就返回。
 *
 * <p>另一点：{@code Application.onCreate} 先于任何 Activity 跑，所以「点开就有记分板」
 * 靠的是 {@link MainActivity} 自己渲染静态缓存：报告没好就显示「检测中」，好了以后
 * 通过 {@link Listener} 回调刷新。UI 线程与后台线程之间只共享 volatile 字段，
 * 且报告对象是**构造完整后**才赋值的（volatile 写建立了 happens-before），不需要加锁读。
 */
public final class LitmusApp extends Application {

    public static final String TAG = "LitmusApp";

    /**
     * 「再跑一次」的触发 action，给 CLI 兜底用：
     * {@code adb shell am broadcast -a io.litmus.canary.RUN -p io.litmus.canary}。
     *
     * <p>为什么用运行期注册而不是清单里声明 receiver：清单文件不在本模块的写作用域里。
     * 运行期 receiver 的代价是**进程必须活着**——但 CLI 的兜底路径是先 {@code am start}
     * 再广播，进程那时一定活着，够用。
     */
    public static final String ACTION_RUN = "io.litmus.canary.RUN";

    /** 状态变化回调（开始 / 完成 / 失败）。回调总在主线程。 */
    public interface Listener {
        void onLitmusStateChanged();
    }

    /** 主线程 Handler：后台线程只能通过它碰 UI。 */
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final Object LOCK = new Object();

    /** 最近一次成功产出的整份 report（可能为 null）。 */
    private static volatile JSONObject sReport;
    /** 最近一次落盘的 report 文件（可能为 null：外部存储不可用时会写内部目录）。 */
    private static volatile File sReportFile;
    /** 失败原因；空串表示没失败。 */
    private static volatile String sError = "";
    private static volatile boolean sRunning;
    /** 每发起一次检测 +1；{@link #sReadyGeneration} 表示最近一次「有结果」的代数。 */
    private static volatile int sGeneration;
    private static volatile int sReadyGeneration;
    private static volatile long sStartedAtMs;
    private static volatile long sFinishedAtMs;
    private static volatile Listener sListener;

    /** 运行期注册的「再跑一次」接收器（Application 活到进程结束，不需要反注册）。 */
    private final BroadcastReceiver runReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent == null ? "" : intent.getAction();
            Log.i(TAG, "broadcast received: " + action);
            requestRun(getApplicationContext());
        }
    };

    // ------------------------------------------------------------------ 生命周期

    @Override
    public void onCreate() {
        super.onCreate();
        // BuildInfo.init 是幂等的（内部 inited 标志），这里先读一次方便日志里看到版本
        BuildInfo.init(this);
        Log.i(TAG, "onCreate: version=" + BuildInfo.version
                + " flavor=" + BuildInfo.flavor
                + " hasNative(baked)=" + BuildInfo.hasNative
                + " expectedCert=" + shortHex(BuildInfo.expectedCertSha256));
        registerRunReceiver();
        // 不阻塞：起线程就返回
        requestRun(this);
    }

    private void registerRunReceiver() {
        try {
            IntentFilter filter = new IntentFilter(ACTION_RUN);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                // API 33+ 必须显式声明导出性；不导出的话 adb shell(uid 2000) 广播会被丢
                registerReceiver(runReceiver, filter, Context.RECEIVER_EXPORTED);
            } else {
                registerReceiver(runReceiver, filter);
            }
            Log.i(TAG, "run receiver ready: " + ACTION_RUN);
        } catch (Throwable t) {
            // 注册失败不影响主路径（am start 已经会跑一次）
            Log.w(TAG, "registerReceiver failed: " + t);
        }
    }

    // ------------------------------------------------------------------ 对外 API

    /**
     * 发起一次检测。已在跑就忽略（连点按钮不会叠线程，也不会出现两份报告互相覆盖）。
     * 重跑时保留旧报告，界面不会先清空再跳回来。
     */
    public static void requestRun(Context c) {
        final Context app = c.getApplicationContext();
        synchronized (LOCK) {
            if (sRunning) {
                return;
            }
            sRunning = true;
            sGeneration++;
            sStartedAtMs = System.currentTimeMillis();
            sFinishedAtMs = 0L;
            sError = "";
            notifyState();
        }
        Thread t = new Thread(() -> execute(app), "litmus-run");
        // 比默认低半级：native 采样 + APK 哈希都是 CPU/IO 密集，别和首帧抢
        t.setPriority(Thread.NORM_PRIORITY - 1);
        t.start();
    }

    public static JSONObject report() {
        return sReport;
    }

    /** 单行 JSON（复制到剪贴板的原文，与落盘/ logcat 完全一致）。 */
    public static String reportJson() {
        JSONObject r = sReport;
        return r == null ? "" : r.toString();
    }

    public static File reportFile() {
        return sReportFile;
    }

    public static String error() {
        return sError;
    }

    public static boolean isRunning() {
        return sRunning;
    }

    public static int generation() {
        return sGeneration;
    }

    /** 最近一次「有结果」（成功或失败）的代数；与 {@link #generation()} 相等即最新。 */
    public static int readyGeneration() {
        return sReadyGeneration;
    }

    /** 最近一次检测耗时（ms）；还没跑完返回 0。 */
    public static long durationMs() {
        long end = sFinishedAtMs;
        long start = sStartedAtMs;
        return (end <= 0 || start <= 0) ? 0L : (end - start);
    }

    public static void setListener(Listener l) {
        sListener = l;
    }

    // ------------------------------------------------------------------ 后台跑

    private static void execute(Context app) {
        JSONObject report = null;
        String error = "";
        File file = null;
        try {
            // 采集 + 全部向量；内部已自带 try/catch，这里再兜一层防 OOM/JNI 崩
            report = LitmusRunner.run(app);
        } catch (Throwable t) {
            error = t.getClass().getSimpleName() + ": " + t.getMessage();
            Log.e(TAG, "LitmusRunner.run failed", t);
        }
        if (report != null) {
            try {
                // 契约 §4.1 / §4.3：落盘 + logcat（tag LitmusReport）
                file = LitmusRunner.publish(app, report);
            } catch (Throwable t) {
                Log.e(TAG, "LitmusRunner.publish failed", t);
            }
        } else if (error.isEmpty()) {
            error = "report is null";
        }

        synchronized (LOCK) {
            sReport = report;
            sReportFile = file;
            sError = error;
            sRunning = false;
            sFinishedAtMs = System.currentTimeMillis();
            sReadyGeneration = sGeneration;
            notifyState();
        }
    }

    private static void notifyState() {
        final Listener l = sListener;
        if (l == null) {
            return;
        }
        MAIN.post(() -> {
            try {
                l.onLitmusStateChanged();
            } catch (Throwable t) {
                Log.w(TAG, "listener threw: " + t);
            }
        });
    }

    private static String shortHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return "-";
        }
        return hex.length() <= 16 ? hex : hex.substring(0, 16) + "…";
    }
}
