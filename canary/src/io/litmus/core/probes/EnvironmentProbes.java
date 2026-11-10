package io.litmus.core.probes;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.ContentResolver;
import android.os.Build;
import android.provider.Settings;
import android.view.accessibility.AccessibilityManager;

import io.litmus.core.LitmusContext;
import io.litmus.core.BuildInfo;
import io.litmus.core.Probe;

import java.util.ArrayList;
import java.util.List;

/**
 * 环境面（应用自身的暴露属性，与设备无关）。
 *
 * <p>只有 {@code env.debuggable} 是 tier A（清单里的硬事实，debuggable 的 release 包一定被
 * 重打包过）；其余是 tier C 的弱信号，只出 CLEAN / SUSPECT / UNKNOWN。
 *
 * <p>干净基线：CI 里靶包是 adb 装到开着「USB 调试」的干净机上，所以 USB adb 与开发者选项
 * **不算痕迹**；只有「无线调试」这种额外暴露面才给弱 SUSPECT。
 */
public final class EnvironmentProbes {

    private EnvironmentProbes() {
    }

    public static List<Probe> list() {
        List<Probe> out = new ArrayList<>(8);
        out.add(new Debuggable());
        out.add(new DeveloperOptions());
        out.add(new ProxyProbe());
        out.add(new CaptureProbe());
        out.add(new OverlayProbe());
        return out;
    }

    /**
     * env.debuggable —— 应用是否带 FLAG_DEBUGGABLE。tier A：这是清单里的硬事实。
     *
     * <p>唯一豁免：构建期 flavor 就是 dev/debug 的包（BuildInfo 里写明），那种包本来就
     * debuggable，只给 SUSPECT，避免开发态自打脸。
     */
    static final class Debuggable implements Probe {
        @Override
        public String id() {
            return "env.debuggable";
        }

        @Override
        public String category() {
            return "environment";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                if (ctx.appSnap == null) {
                    sink.unknown("snapshot unavailable");
                    return;
                }
                String flavor = Ev.nz(BuildInfo.flavor).toLowerCase();
                boolean devBuild = flavor.contains("dev") || flavor.contains("debug");
                if (!ctx.appSnap.debuggable) {
                    sink.clean("not debuggable (sdk=" + Build.VERSION.SDK_INT + ")");
                } else if (devBuild) {
                    sink.suspect("FLAG_DEBUGGABLE set on flavor=" + Ev.nz(BuildInfo.flavor), 0.4);
                } else {
                    sink.tampered("FLAG_DEBUGGABLE set on flavor=" + Ev.nz(BuildInfo.flavor)
                            + " (sdk=" + Build.VERSION.SDK_INT + ")", 0.95);
                }
            } catch (Throwable t) {
                sink.error("env.debuggable: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * env.developer —— 开发者选项 / adb 暴露面。tier C。
     *
     * <p>USB adb 是靶包安装与测试的**前提**，不能当痕迹（否则干净机永远拿不到满分）；
     * 只有无线调试（adb_wifi_enabled / adb tcp port）才给弱 SUSPECT。
     */
    static final class DeveloperOptions implements Probe {
        @Override
        public String id() {
            return "env.developer";
        }

        @Override
        public String category() {
            return "environment";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                int adb = globalInt(ctx.app.getContentResolver(), "adb_enabled");
                int dev = globalInt(ctx.app.getContentResolver(), "development_settings_enabled");
                int wifiAdb = globalInt(ctx.app.getContentResolver(), "adb_wifi_enabled");
                ctx.facts.put("env.adb_enabled", adb)
                        .put("env.development_settings", dev)
                        .put("env.adb_wifi", wifiAdb);

                if (adb < 0 && dev < 0 && wifiAdb < 0) {
                    sink.unknown("Settings.Global unreadable");
                } else if (wifiAdb == 1) {
                    sink.suspect("wireless adb enabled (adb=" + adb + " dev=" + dev + ")", 0.5);
                } else {
                    sink.clean("adb=" + adb + " dev=" + dev + " wifiAdb=" + wifiAdb
                            + " (usb adb is test baseline)");
                }
            } catch (Throwable t) {
                sink.error("env.developer: " + t.getClass().getSimpleName());
            }
        }
    }

    /** env.proxy —— 全局 HTTP 代理 / java proxy 属性。tier C，权重 2。 */
    static final class ProxyProbe implements Probe {
        @Override
        public String id() {
            return "env.proxy";
        }

        @Override
        public String category() {
            return "environment";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                String global = "";
                boolean readable = false;
                try {
                    ContentResolver cr = ctx.app.getContentResolver();
                    String v = Settings.Global.getString(cr, Settings.Global.HTTP_PROXY);
                    global = Ev.nz(v).trim();
                    readable = true;
                } catch (Throwable ignored) {
                    // 读不到就只看 java 属性
                }
                String host = Ev.nz(System.getProperty("http.proxyHost")).trim();
                String port = Ev.nz(System.getProperty("http.proxyPort")).trim();
                ctx.facts.put("env.http_proxy", global).put("env.proxy_host", host);

                boolean globalSet = !global.isEmpty() && !":0".equals(global) && !"0".equals(global);
                if (!host.isEmpty()) {
                    sink.suspect("java proxy=" + Ev.clip(host + ":" + port, 60), 0.5);
                } else if (globalSet) {
                    sink.suspect("global http_proxy=" + Ev.clip(global, 60), 0.5);
                } else if (!readable) {
                    sink.unknown("Settings.Global.HTTP_PROXY unreadable");
                } else {
                    sink.clean("no proxy (global=" + Ev.clip(global, 20) + ")");
                }
            } catch (Throwable t) {
                sink.error("env.proxy: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * env.capture —— 无障碍 / 录屏类辅助服务。tier C，权重 2。
     *
     * <p>无障碍服务能读屏并模拟点击，是自动化取证/外挂的主要通道。
     */
    static final class CaptureProbe implements Probe {
        @Override
        public String id() {
            return "env.capture";
        }

        @Override
        public String category() {
            return "environment";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                AccessibilityManager am = (AccessibilityManager) ctx.app
                        .getSystemService(android.content.Context.ACCESSIBILITY_SERVICE);
                if (am == null) {
                    sink.unknown("AccessibilityManager unavailable");
                    return;
                }
                List<AccessibilityServiceInfo> list =
                        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
                int n = list == null ? 0 : list.size();
                String first = "";
                if (n > 0 && list.get(0) != null) {
                    first = Ev.nz(list.get(0).getId());
                }
                ctx.facts.put("env.a11y.enabled", n)
                        .put("env.a11y.first", Ev.clip(first, 90));

                if (n > 0) {
                    sink.suspect("a11y services=" + n + " e0=" + Ev.clip(first, 70), 0.4);
                } else {
                    sink.clean("no accessibility service enabled");
                }
            } catch (Throwable t) {
                sink.error("env.capture: " + t.getClass().getSimpleName());
            }
        }
    }

    /** env.overlay —— 悬浮窗权限。tier C，权重 2。 */
    static final class OverlayProbe implements Probe {
        @Override
        public String id() {
            return "env.overlay";
        }

        @Override
        public String category() {
            return "environment";
        }

        @Override
        public int weight() {
            return 2;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                boolean can = Settings.canDrawOverlays(ctx.app);
                ctx.facts.put("env.overlay.can", can);
                if (can) {
                    sink.suspect("SYSTEM_ALERT_WINDOW granted", 0.45);
                } else {
                    sink.clean("no overlay permission");
                }
            } catch (Throwable t) {
                sink.error("env.overlay: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ 工具

    private static int globalInt(ContentResolver cr, String key) {
        try {
            return Settings.Global.getInt(cr, key, -1);
        } catch (Throwable t) {
            return -1;
        }
    }
}
