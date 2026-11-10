package io.litmus.core.probes;

import android.content.pm.PackageManager;
import android.os.Build;

import io.litmus.core.LitmusContext;
import io.litmus.core.Probe;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * 提权面（设备平面，Momo 那套）。tier C 为主，SUSPECT 封顶。
 *
 * <p>关键设计：**干净基线**。很多 ROM / 模拟器天生「脏」（ro.debuggable=1、
 * /system 是 overlay 挂载），直接判 TAMPERED 会让分数全是红的 —— 这正是 Momo 被诟病的点。
 * 所以这里只报事实 + 弱结论，由 CLI 的 baseline 归一处理（见 docs/03-评分模型.md §4）。
 *
 * <p>唯一例外是 {@code priv.proc.uid}：uid 区间是硬不变量（应用不可能是 root/system），
 * 所以它是 tier A 并且允许 TAMPERED。
 */
public final class PrivilegeProbes {

    private PrivilegeProbes() {
    }

    public static List<Probe> list() {
        List<Probe> out = new ArrayList<>(10);
        out.add(new ProcUid());
        out.add(new SuBinary());
        out.add(new Magisk());
        out.add(new KernelPatch());
        out.add(new PropsProbe());
        out.add(new Mounts());
        out.add(new Selinux());
        return out;
    }

    // ------------------------------------------------------------------ A：不变量

    /**
     * priv.proc.uid —— 进程 uid 区间与多视图一致性。
     *
     * <p>A 级不变量：普通应用（走 zygote fork 的 untrusted_app）uid 一定 >= 10000；
     * uid 0/1000/2000/1013 只可能来自 root、系统进程或运行时提权。三处读数还不一致，
     * 说明有人在伪造 /proc 视图。
     */
    static final class ProcUid implements Probe {
        @Override
        public String id() {
            return "priv.proc.uid";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 5;
        }

        @Override
        public String tier() {
            return "A";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                int uid = android.os.Process.myUid();
                int snapUid = ctx.appSnap == null ? -1 : ctx.appSnap.uid;
                int statusUid = ProcFs.statusInt("Uid");
                ctx.facts.put("priv.uid.java", uid)
                        .put("priv.uid.snapshot", snapUid)
                        .put("priv.uid.status", statusUid);

                if (uid < 10000) {
                    sink.tampered("uid=" + uid + " (<10000: root/system/shell)", 1.0);
                } else if (statusUid >= 0 && statusUid != uid) {
                    sink.tampered("uid java=" + uid + " status=" + statusUid + " (views disagree)", 0.95);
                } else if (snapUid >= 0 && snapUid != uid) {
                    sink.suspect("uid java=" + uid + " snapshot=" + snapUid, 0.6);
                } else {
                    sink.clean("uid=" + uid + " (app range, views agree)");
                }
            } catch (Throwable t) {
                sink.error("priv.proc.uid: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ C：特征匹配

    /** priv.su —— 常见 su 路径是否存在且可执行。tier C：用户可能只是装了 Magisk 未授权。 */
    static final class SuBinary implements Probe {
        private static final String[] CANDIDATES = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
                "/data/local/su", "/data/local/xbin/su", "/data/local/bin/su",
                "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/adb/ksu/bin/su",
                "/debug_ramdisk/su", "/data/adb/su", "/cache/su",
        };

        @Override
        public String id() {
            return "priv.su";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                List<String> hit = new ArrayList<>();
                for (String p : CANDIDATES) {
                    try {
                        File f = new File(p);
                        if (f.exists() && f.canExecute() && hit.size() < 4) {
                            hit.add(p);
                        }
                    } catch (Throwable ignored) {
                        // 无权限 stat 就跳过，不算痕迹
                    }
                }
                ctx.facts.put("priv.su", hit);
                if (hit.isEmpty()) {
                    sink.clean("no su binary in " + CANDIDATES.length + " common paths");
                } else {
                    sink.suspect("su=" + Ev.clipList(hit, 3), 0.55);
                }
            } catch (Throwable t) {
                sink.error("priv.su: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * priv.magisk —— Magisk 目录 / 属性 / 包名。tier C。
     *
     * <p>/data/adb 对普通应用是 EACCES（所以路径检查基本只能拿 false，无害也无用），
     * 真正有效的是**已安装包名**与 /proc/mounts 里的 magisk 挂载源。
     */
    static final class Magisk implements Probe {
        private static final String[] PATHS = {
                "/data/adb/magisk", "/data/adb/modules", "/data/adb/magisk.db",
                "/sbin/.magisk", "/cache/.disable_magisk", "/init.magisk.rc", "/debug_ramdisk",
        };
        private static final String[] PKGS = {
                "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
                "com.kingroot.kinguser", "eu.chainfire.supersu", "me.weishu.kernelsu",
                "me.bmax.apatch", "com.rifsxd.ksunext",
        };

        @Override
        public String id() {
            return "priv.magisk";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                List<String> hits = new ArrayList<>();
                for (String p : PATHS) {
                    try {
                        if (new File(p).exists() && hits.size() < 4) {
                            hits.add("path:" + Ev.base(p));
                        }
                    } catch (Throwable ignored) {
                        // stat 被拒
                    }
                }

                boolean[] broken = new boolean[1];
                PackageManager pm = ctx.app.getPackageManager();
                for (String pkg : PKGS) {
                    try {
                        pm.getPackageInfo(pkg, 0);
                        if (hits.size() < 4) {
                            hits.add("pkg:" + pkg);
                        }
                    } catch (PackageManager.NameNotFoundException ignored) {
                        // 没装
                    } catch (Throwable t) {
                        broken[0] = true;
                    }
                }

                String mounts = ProcFs.readText("/proc/mounts", 512 * 1024);
                if (mounts != null && mounts.toLowerCase().contains("magisk") && hits.size() < 4) {
                    hits.add("mount:magisk");
                }
                ctx.facts.put("priv.magisk.hits", hits);

                if (!hits.isEmpty()) {
                    sink.suspect("magisk trace=" + Ev.clipList(hits, 3), 0.55);
                } else if (broken[0]) {
                    sink.unknown("package query denied (QUERY_ALL_PACKAGES?)");
                } else {
                    sink.clean("no magisk path/pkg/mount");
                }
            } catch (Throwable t) {
                sink.error("priv.magisk: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * priv.kernel —— KernelSU/APatch 内核面。/proc/version 是内核对所有进程开放的窗口，
     * 打了 KSU 补丁的内核通常会在版本串里留下痕迹。tier C。
     */
    static final class KernelPatch implements Probe {
        private static final String[] MARKS = {
                "kernelsu", "ksunext", "sukisu", "apatch", "rkernelsu",
        };

        @Override
        public String id() {
            return "priv.kernel";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                String ver = ProcFs.readText("/proc/version", 8192);
                if (ver == null) {
                    sink.unknown("/proc/version unreadable");
                    return;
                }
                String lower = ver.toLowerCase();
                String hit = "";
                for (String m : MARKS) {
                    if (lower.contains(m)) {
                        hit = m;
                        break;
                    }
                }
                List<String> dirs = new ArrayList<>();
                for (String p : new String[]{"/data/adb/ksud", "/data/adb/ksu", "/data/adb/apatch"}) {
                    try {
                        if (new File(p).exists() && dirs.size() < 3) {
                            dirs.add(Ev.base(p));
                        }
                    } catch (Throwable ignored) {
                        // 忽略
                    }
                }
                ctx.facts.put("priv.kernel.version", Ev.clip(ver.trim(), 120))
                        .put("priv.kernel.dirs", dirs);

                if (!hit.isEmpty()) {
                    sink.suspect("kernel marker=" + hit + " version="
                            + Ev.clip(ver.trim(), 90), 0.6);
                } else if (!dirs.isEmpty()) {
                    sink.suspect("kernel root dir=" + Ev.clipList(dirs, 2), 0.5);
                } else {
                    sink.clean("kernel version has no ksu/apatch marker");
                }
            } catch (Throwable t) {
                sink.error("priv.kernel: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * priv.props —— ro.debuggable / ro.secure / service.adb.root。tier C。
     *
     * <p>三处取值来源按可靠性降级：SystemProperties（反射，隐藏 API 可能被拦）→
     * /system/build.prop（多数 ROM 可读）。都拿不到就 UNKNOWN，绝不当成干净。
     */
    static final class PropsProbe implements Probe {
        @Override
        public String id() {
            return "priv.props";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "C";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                String debug = prop("ro.debuggable");
                String secure = prop("ro.secure");
                String adbRoot = prop("service.adb.root");
                ctx.facts.put("priv.prop.debuggable", debug)
                        .put("priv.prop.secure", secure)
                        .put("priv.prop.adbRoot", adbRoot);

                boolean all = debug.isEmpty() && secure.isEmpty() && adbRoot.isEmpty();
                if (all) {
                    sink.unknown("props unreadable (hidden API blocked + build.prop denied)");
                } else if ("1".equals(debug)) {
                    sink.suspect("ro.debuggable=1 (secure=" + secure + ")", 0.5);
                } else if ("0".equals(secure)) {
                    sink.suspect("ro.secure=0 (debuggable=" + debug + ")", 0.5);
                } else if ("1".equals(adbRoot)) {
                    sink.suspect("service.adb.root=1", 0.55);
                } else {
                    sink.clean("ro.debuggable=" + debug + " ro.secure=" + secure
                            + " service.adb.root=" + adbRoot);
                }
            } catch (Throwable t) {
                sink.error("priv.props: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ B：交叉视图

    /**
     * priv.mounts —— /proc/mounts 异常挂载。tier B。
     *
     * <p>看两件事：系统分区是不是被 overlay/tmpfs/rw 挂过（Magisk 的 overlay 面具、改装
     * ROM），以及挂载源里有没有 magisk/worker/apatch/ksu 字样。干净机这些分区恒为 ro。
     */
    static final class Mounts implements Probe {
        @Override
        public String id() {
            return "priv.mounts";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                String txt = ProcFs.readText("/proc/mounts", 512 * 1024);
                if (txt == null) {
                    sink.unknown("/proc/mounts unreadable");
                    return;
                }
                List<String> anomalies = new ArrayList<>();
                int lines = 0;
                int from = 0;
                while (from < txt.length() && lines < 4096) {
                    int e = txt.indexOf('\n', from);
                    if (e < 0) {
                        e = txt.length();
                    }
                    if (e > from) {
                        lines++;
                        String line = txt.substring(from, e);
                        String[] f = line.split(" ", 4);
                        if (f.length >= 4) {
                            String src = f[0].toLowerCase();
                            String mnt = f[1];
                            String fstype = f[2].toLowerCase();
                            String opts = f[3].toLowerCase();
                            if (src.contains("magisk") || src.contains("worker")
                                    || src.contains("apatch") || src.contains("ksu")) {
                                if (anomalies.size() < 6) {
                                    anomalies.add("src:" + mnt);
                                }
                            } else if (isSystemMount(mnt)) {
                                if ("overlay".equals(fstype) || "tmpfs".equals(fstype)) {
                                    if (anomalies.size() < 6) {
                                        anomalies.add(fstype + ":" + mnt);
                                    }
                                } else if (opts.startsWith("rw")) {
                                    if (anomalies.size() < 6) {
                                        anomalies.add("rw:" + mnt);
                                    }
                                }
                            }
                        }
                    }
                    from = e + 1;
                }
                ctx.facts.put("priv.mounts.lines", lines).put("priv.mounts.anomalies", anomalies);

                boolean suFamily = false;
                for (String a : anomalies) {
                    if (a.startsWith("src:")) {
                        suFamily = true;
                        break;
                    }
                }
                if (anomalies.isEmpty()) {
                    sink.clean("mounts=" + lines + " system/vendor all ro");
                } else if (suFamily) {
                    sink.suspect("su-family mount=" + Ev.clipList(anomalies, 3), 0.75);
                } else {
                    sink.suspect("mount anomalies n=" + anomalies.size() + " "
                            + Ev.clipList(anomalies, 3), 0.6);
                }
            } catch (Throwable t) {
                sink.error("priv.mounts: " + t.getClass().getSimpleName());
            }
        }

        /**
         * 只看**分区根**：/vendor/firmware_mnt 这类子挂载（vfat、rw）在干净 Pixel 上就存在，
         * 拿 startsWith 判会把干净机打成 SUSPECT，所以这里只做精确匹配。
         */
        private static boolean isSystemMount(String mnt) {
            return "/system".equals(mnt) || "/vendor".equals(mnt) || "/product".equals(mnt)
                    || "/system_ext".equals(mnt) || "/odm".equals(mnt)
                    || "/system_root".equals(mnt);
        }
    }

    /**
     * priv.selinux —— getenforce / selinuxfs / 进程域。tier B。
     *
     * <p>permissive 或者 selinuxfs 没挂，等于 MAC 失效；进程域出现 magisk/ksu 说明跑在
     * root 域里。
     */
    static final class Selinux implements Probe {
        @Override
        public String id() {
            return "priv.selinux";
        }

        @Override
        public String category() {
            return "privilege";
        }

        @Override
        public int weight() {
            return 3;
        }

        @Override
        public String tier() {
            return "B";
        }

        @Override
        public void run(LitmusContext ctx, Sink sink) {
            try {
                String enforce = null;
                try {
                    Class<?> sc = Class.forName("android.os.SELinux");
                    Method m = sc.getMethod("isSELinuxEnforced");
                    Object v = m.invoke(null);
                    if (v instanceof Boolean) {
                        enforce = ((Boolean) v) ? "1" : "0";
                    }
                } catch (Throwable ignored) {
                    // 隐藏 API 被拦就走文件
                }
                if (enforce == null) {
                    String f = ProcFs.readText("/sys/fs/selinux/enforce", 64);
                    if (f != null && !f.trim().isEmpty()) {
                        enforce = f.trim();
                    }
                }
                String attr = ProcFs.readText("/proc/self/attr/current", 512);
                String domain = attr == null ? "" : attr.trim();
                String mounts = ProcFs.readText("/proc/mounts", 512 * 1024);
                boolean hasSelinuxfs = mounts != null && mounts.contains("selinuxfs");

                ctx.facts.put("priv.selinux.enforce", Ev.nz(enforce))
                        .put("priv.selinux.domain", Ev.clip(domain, 90))
                        .put("priv.selinux.hasSelinuxfs", hasSelinuxfs);

                String lower = domain.toLowerCase();
                if (lower.contains("magisk") || lower.contains(":ksu") || lower.contains("su_domain")) {
                    sink.suspect("process domain=" + Ev.clip(domain, 90), 0.8);
                } else if ("0".equals(enforce)) {
                    sink.suspect("selinux permissive (enforce=0) domain=" + Ev.clip(domain, 60), 0.75);
                } else if (enforce == null && !hasSelinuxfs) {
                    sink.suspect("no selinuxfs in /proc/mounts (SELinux off)", 0.7);
                } else if (enforce == null) {
                    sink.unknown("enforce unreadable (hidden API + /sys denied), selinuxfs present");
                } else {
                    sink.clean("selinux enforcing, domain=" + Ev.clip(domain, 70), 0.9);
                }
            } catch (Throwable t) {
                sink.error("priv.selinux: " + t.getClass().getSimpleName());
            }
        }
    }

    // ------------------------------------------------------------------ 属性读取（包内复用）

    private static volatile boolean buildPropLoaded;
    private static volatile String buildPropText;

    /**
     * 读一个系统属性。先试 SystemProperties（反射），失败退 /system/build.prop。
     * 读不到返回 ""（空串），调用方据此判 UNKNOWN。
     */
    static String prop(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            Object v = get.invoke(null, key, "");
            if (v instanceof String && !((String) v).isEmpty()) {
                return ((String) v).trim();
            }
        } catch (Throwable ignored) {
            // 隐藏 API 被限制：退文件
        }
        return buildProp(key);
    }

    private static String buildProp(String key) {
        if (!buildPropLoaded) {
            buildPropText = ProcFs.readText("/system/build.prop", 1024 * 1024);
            buildPropLoaded = true;
        }
        String txt = buildPropText;
        if (txt == null || txt.isEmpty()) {
            return "";
        }
        String want = key + "=";
        int from = 0;
        while (from < txt.length()) {
            int e = txt.indexOf('\n', from);
            if (e < 0) {
                e = txt.length();
            }
            if (txt.startsWith(want, from)) {
                return txt.substring(from + want.length(), e).trim();
            }
            from = e + 1;
        }
        return "";
    }

    /** 供其它 probe 复用：Build 里有没有 userdebug/test-keys 这类开发态标记。 */
    static boolean isUserdebugBuild() {
        try {
            String tags = Ev.nz(Build.TAGS).toLowerCase();
            String type = Ev.nz(Build.TYPE).toLowerCase();
            return tags.contains("test-keys") || "userdebug".equals(type) || "eng".equals(type);
        } catch (Throwable t) {
            return false;
        }
    }
}
