package io.litmus.core.probes;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.UserHandle;
import android.os.UserManager;

import io.litmus.core.LitmusContext;
import io.litmus.core.Probe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 虚拟化 / 多开 / 模拟器。tier C（全部只出 CLEAN / SUSPECT / UNKNOWN）。
 *
 * <p>同样受「干净基线」约束：MuMu / 雷电这类模拟器的 Build 字段天生就是 qemu 味，
 * 必须先跑一次 baseline 再比较，否则任何人在模拟器上都是 0 分。
 *
 * <p>其中 {@code virt.vapp} 的两条判据（codePath 目录名、dataDir 后缀）接近不变量，
 * 但仍然按 tier C 处理：某些深度定制 ROM 的路径结构本身就怪，不值得为它押上 TAMPERED。
 */
public final class VirtualizationProbes {

    private VirtualizationProbes() {
    }

    public static List<Probe> list() {
        List<Probe> out = new ArrayList<>(8);
        out.add(new EmulatorBuild());
        out.add(new EmulatorFiles());
        out.add(new EmulatorHardware());
        out.add(new Vapp());
        out.add(new MultiUser());
        return out;
    }

    /** virt.emulator.props —— Build / 属性里的模拟器指纹。tier C。 */
    static final class EmulatorBuild implements Probe {
        private static final String[] MARKS = {
                "goldfish", "ranchu", "qemu", "vbox", "genymotion", "andy", "nox",
                "bluestacks", "ttvm", "microvirt", "mumu", "nemu", "shamrock",
                "droid4x", "memu", "netease",
        };

        @Override
        public String id() {
            return "virt.emulator.props";
        }

        @Override
        public String category() {
            return "virtualization";
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
                String blob = (Build.HARDWARE + "|" + Build.PRODUCT + "|" + Build.BOARD + "|"
                        + Build.BRAND + "|" + Build.DEVICE + "|" + Build.MODEL + "|"
                        + Build.MANUFACTURER + "|" + Build.FINGERPRINT + "|"
                        + Build.HOST + "|" + Ev.nz(Build.TAGS)).toLowerCase();
                String hit = "";
                for (String m : MARKS) {
                    if (blob.contains(m)) {
                        hit = m;
                        break;
                    }
                }
                // ro.hardware/ro.product.* 从反射或 build.prop 再补一刀
                String prop = PrivilegeProbes.prop("ro.hardware").toLowerCase()
                        + "|" + PrivilegeProbes.prop("ro.kernel.qemu").toLowerCase()
                        + "|" + PrivilegeProbes.prop("ro.build.flavor").toLowerCase();
                boolean qemuProp = prop.contains("goldfish") || prop.contains("ranchu")
                        || prop.contains("qemu");
                boolean testKeys = Ev.nz(Build.TAGS).toLowerCase().contains("test-keys");

                ctx.facts.put("virt.build.hardware", Ev.nz(Build.HARDWARE))
                        .put("virt.build.fingerprint", Ev.nz(Build.FINGERPRINT))
                        .put("virt.build.tags", Ev.nz(Build.TAGS));

                if (!hit.isEmpty()) {
                    sink.suspect("build hit=" + hit + " (" + Ev.nz(Build.MANUFACTURER) + "/"
                            + Ev.nz(Build.MODEL) + ")", 0.6);
                } else if (qemuProp) {
                    sink.suspect("prop hit (ro.hardware/ro.kernel.qemu)", 0.55);
                } else if (testKeys) {
                    sink.suspect("build tags=test-keys (" + Ev.clip(Build.FINGERPRINT, 80) + ")", 0.35);
                } else {
                    sink.clean("no emulator marker in Build/props");
                }
            } catch (Throwable t) {
                sink.error("virt.emulator.props: " + t.getClass().getSimpleName());
            }
        }
    }

    /** virt.emulator.files —— 模拟器特有的设备节点 / 库文件。tier C。 */
    static final class EmulatorFiles implements Probe {
        private static final String[] PATHS = {
                "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud",
                "/dev/socket/genyd", "/dev/qemu_trace", "/sys/qemu_trace",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/system/lib64/libc_malloc_debug_qemu.so",
                "/system/bin/qemud", "/dev/bstfolder",
        };

        @Override
        public String id() {
            return "virt.emulator.files";
        }

        @Override
        public String category() {
            return "virtualization";
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
                        if (new java.io.File(p).exists() && hits.size() < 4) {
                            hits.add(p);
                        }
                    } catch (Throwable ignored) {
                        // stat 被拒就跳过
                    }
                }
                ctx.facts.put("virt.emulator.files", hits);
                if (hits.isEmpty()) {
                    sink.clean("no emulator device node in " + PATHS.length + " paths");
                } else {
                    sink.suspect("emulator files=" + Ev.clipList(hits, 3), 0.55);
                }
            } catch (Throwable t) {
                sink.error("virt.emulator.files: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * virt.emulator.hardware —— CPU 核数 / 传感器数量。tier C，权重压到 2。
     *
     * <p>阈值放很松：干净的低端机也可能 2 核，所以只有 1 核或「一个传感器都没有」才给弱 SUSPECT。
     */
    static final class EmulatorHardware implements Probe {
        @Override
        public String id() {
            return "virt.emulator.hardware";
        }

        @Override
        public String category() {
            return "virtualization";
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
                int cores = Runtime.getRuntime().availableProcessors();
                int sensors = -1;
                try {
                    SensorManager sm = (SensorManager) ctx.app.getSystemService(Context.SENSOR_SERVICE);
                    if (sm != null) {
                        List<Sensor> list = sm.getSensorList(Sensor.TYPE_ALL);
                        sensors = list == null ? -1 : list.size();
                    }
                } catch (Throwable ignored) {
                    // 传感器服务拿不到就不判这一项
                }
                ctx.facts.put("virt.cpu.cores", cores).put("virt.sensor.count", sensors);

                if (sensors == 0) {
                    sink.suspect("cores=" + cores + " sensors=0 (emulator-like)", 0.45);
                } else if (cores <= 1) {
                    sink.suspect("cores=1 sensors=" + sensors + " (single-core)", 0.4);
                } else {
                    sink.clean("cores=" + cores + " sensors=" + sensors);
                }
            } catch (Throwable t) {
                sink.error("virt.emulator.hardware: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * virt.vapp —— VirtualApp / 多开容器。tier C。
     *
     * <p>三条判据：
     * <ol>
     *   <li>codePath 的父目录名不以本包名开头（容器宿主目录）；</li>
     *   <li>dataDir 不以 /包名 结尾（容器重映射了数据目录）；</li>
     *   <li>maps 里出现容器库名，或已安装容器宿主包。</li>
     * </ol>
     */
    static final class Vapp implements Probe {
        private static final String[] MARKS = {
                "libva++", "libvirtual", "virtualapp", "lody", "ex.virtualapp",
                "io.virtualapp", "dualaid", "parallel", "multiopen", "virtualspace",
                "moxie", "sandvxposed", "vxp",
        };
        private static final String[] HOSTS = {
                "com.lody.virtual", "io.virtualapp", "com.lbe.parallel.intl",
                "com.excelliance.dualaid", "com.parallel.space.lite",
                "com.multiopen.assistant", "com.bly.dkplat", "com.qihoo.magic",
        };

        @Override
        public String id() {
            return "virt.vapp";
        }

        @Override
        public String category() {
            return "virtualization";
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
                String pkg = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.packageName);
                String codePath = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.codePath);
                String dataDir = ctx.appSnap == null ? "" : Ev.nz(ctx.appSnap.dataDir);

                if (!pkg.isEmpty() && !codePath.isEmpty()) {
                    String leaf = Ev.base(Ev.dirOf(codePath));
                    if (!leaf.isEmpty() && !leaf.startsWith(pkg)) {
                        hits.add("codeDir:" + Ev.clip(leaf, 60));
                    }
                }
                if (!pkg.isEmpty() && !dataDir.isEmpty() && !dataDir.endsWith("/" + pkg)) {
                    hits.add("dataDir:" + Ev.clip(dataDir, 60));
                }

                List<ProcFs.Region> maps = ProcFs.mapsOrNull();
                if (maps != null) {
                    Set<String> seen = new HashSet<>();
                    for (ProcFs.Region r : maps) {
                        String lower = r.path.toLowerCase();
                        if (lower.isEmpty() || !seen.add(lower)) {
                            continue;
                        }
                        for (String m : MARKS) {
                            if (lower.contains(m)) {
                                if (hits.size() < 4) {
                                    hits.add("lib:" + Ev.clip(Ev.base(r.path), 40));
                                }
                                break;
                            }
                        }
                    }
                }

                try {
                    android.content.pm.PackageManager pm = ctx.app.getPackageManager();
                    for (String h : HOSTS) {
                        try {
                            pm.getPackageInfo(h, 0);
                            if (hits.size() < 4) {
                                hits.add("pkg:" + h);
                            }
                        } catch (Throwable ignored) {
                            // 没装 / 不可见
                        }
                    }
                } catch (Throwable ignored) {
                    // PM 不可用不影响前两条判据
                }

                ctx.facts.put("virt.vapp.hits", hits);
                if (!hits.isEmpty()) {
                    sink.suspect("vapp trace=" + Ev.clipList(hits, 3), 0.6);
                } else {
                    sink.clean("codeDir/dataDir/libs match own package");
                }
            } catch (Throwable t) {
                sink.error("virt.vapp: " + t.getClass().getSimpleName());
            }
        }
    }

    /**
     * virt.multi.user —— 多用户 / 工作资料 / 应用克隆空间。tier C，权重 2。
     *
     * <p>userId = uid / 100000。正常是 0；工作资料是 10+；克隆器（如 Island / 双开）会把
     * 应用放进 10 以上的用户空间或 uid 999 这种「不可能的空间」。
     */
    static final class MultiUser implements Probe {
        @Override
        public String id() {
            return "virt.multi.user";
        }

        @Override
        public String category() {
            return "virtualization";
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
                int uid = android.os.Process.myUid();
                // userId 直接取自 uid 的高位（AID 编码：userId * 100000 + appId）
                int userId = uid / 100000;
                int profiles = -1;
                try {
                    UserManager um = (UserManager) ctx.app.getSystemService(Context.USER_SERVICE);
                    if (um != null) {
                        List<UserHandle> list = um.getUserProfiles();
                        profiles = list == null ? -1 : list.size();
                    }
                } catch (Throwable ignored) {
                    // 拿不到 UserManager 就用 uid 推
                }
                ctx.facts.put("virt.user.id", userId)
                        .put("virt.user.profiles", profiles)
                        .put("virt.user.uid", uid);

                if (userId >= 10) {
                    sink.suspect("userId=" + userId + " profiles=" + profiles
                            + " (clone/isolated space)", 0.5);
                } else if (profiles > 1) {
                    sink.suspect("user profiles=" + profiles + " (work profile)", 0.3);
                } else if (profiles < 0) {
                    sink.unknown("UserManager unavailable (userId=" + userId + ")");
                } else {
                    sink.clean("userId=" + userId + " profiles=" + profiles);
                }
            } catch (Throwable t) {
                sink.error("virt.multi.user: " + t.getClass().getSimpleName());
            }
        }
    }
}
