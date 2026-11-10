package io.litmus.core;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Process;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 包/进程/签名的一次性快照。契约见 docs/04-契约.md §1.4。
 *
 * <p>一次采样、全局复用：所有 pkg.* 向量必须基于同一份快照判定，否则会出现
 * 「签名对得上但哈希对不上」这种自相矛盾的报告。
 */
@SuppressWarnings("deprecation")
public final class AppSnapshot {

    public final String packageName;
    public final int pid;
    public final int uid;
    public final String processName;
    public final String codePath;
    public final String dataDir;
    public final boolean debuggable;
    public final int targetSdk;
    public final String installer;

    /** GET_SIGNATURES 路径（旧 flags），每项为证书 DER 的 SHA-256 小写 hex。 */
    public final List<String> installCerts;
    /** GET_SIGNING_CERTIFICATES → apkContentsSigners。 */
    public final List<String> signingCerts;
    /** getSigningCertificateHistory()。 */
    public final List<String> certHistory;
    public final boolean multipleSigners;

    /** codePath 文件内容 SHA-256（CLI 平面用它对比原始包哈希）。 */
    public final String apkSha256;
    /** ZipEntry 指纹，算法见契约 §4.4（Java / Python 必须逐字节一致）。 */
    public final String zipFingerprint;
    /** classes*.dex 条目数与总大小，用于粗判 dex 是否被增删。 */
    public final int dexCount;
    public final long dexBytes;
    /** appComponentFactory / appClass 的原始值（被打包器改过就是痕迹）。 */
    public final String appComponentFactory;
    public final String appClass;

    private AppSnapshot(Context c) throws Exception {
        final PackageManager pm = c.getPackageManager();
        this.packageName = c.getPackageName();
        this.pid = Process.myPid();
        this.uid = Process.myUid();
        this.codePath = c.getApplicationInfo().sourceDir;
        this.dataDir = c.getApplicationInfo().dataDir;
        this.processName = currentProcessName();

        final ApplicationInfo ai = c.getApplicationInfo();
        this.debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        this.targetSdk = ai.targetSdkVersion;
        this.appComponentFactory = ai.appComponentFactory == null ? "" : ai.appComponentFactory;
        this.appClass = ai.className == null ? "" : ai.className;

        PackageInfo pi = pm.getPackageInfo(packageName,
                PackageManager.GET_SIGNATURES | PackageManager.GET_SIGNING_CERTIFICATES);

        List<String> legacy = new ArrayList<>();
        if (pi.signatures != null) {
            for (Signature s : pi.signatures) {
                legacy.add(sha256Hex(s.toByteArray()));
            }
        }
        this.installCerts = Collections.unmodifiableList(legacy);

        List<String> v3 = new ArrayList<>();
        List<String> hist = new ArrayList<>();
        boolean multi = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            SigningInfo si = pi.signingInfo;
            if (si != null) {
                Signature[] signers = si.getApkContentsSigners();
                if (signers != null) {
                    for (Signature s : signers) {
                        v3.add(sha256Hex(s.toByteArray()));
                    }
                }
                Signature[] history = si.getSigningCertificateHistory();
                if (history != null) {
                    for (Signature s : history) {
                        hist.add(sha256Hex(s.toByteArray()));
                    }
                }
                multi = si.hasMultipleSigners();
            }
        } else {
            v3.addAll(legacy);
        }
        this.signingCerts = Collections.unmodifiableList(v3);
        this.certHistory = Collections.unmodifiableList(hist);
        this.multipleSigners = multi;

        this.installer = safeInstaller(pm, packageName);

        String sha = "";
        try {
            sha = sha256File(new File(codePath));
        } catch (Throwable ignored) {
        }
        this.apkSha256 = sha;

        String fp = "";
        int dc = -1;
        long db = 0L;
        try {
            File apk = new File(codePath);
            ZipFile zf = new ZipFile(apk);
            try {
                StringBuilder sb = new StringBuilder();
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    sb.append(e.getName()).append('|')
                            .append(String.format("%08x", e.getCrc())).append('|')
                            .append(e.getSize()).append('|')
                            .append(e.getCompressedSize()).append('|')
                            .append(e.getMethod()).append('\n');
                    String nm = e.getName();
                    if (nm.startsWith("classes") && nm.endsWith(".dex")) {
                        dc = (dc < 0 ? 0 : dc) + 1;
                        db += e.getSize();
                    }
                }
                fp = sha256Hex(sb.toString().getBytes("UTF-8"));
            } finally {
                zf.close();
            }
        } catch (Throwable ignored) {
        }
        this.zipFingerprint = fp;
        this.dexCount = dc;
        this.dexBytes = db;
    }

    public static AppSnapshot capture(Context c) throws Exception {
        return new AppSnapshot(c);
    }

    private static String currentProcessName() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return android.app.Application.getProcessName();
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    private static String safeInstaller(PackageManager pm, String pkg) {
        try {
            String s = pm.getInstallerPackageName(pkg);
            return s == null ? "" : s;
        } catch (Throwable t) {
            return "";
        }
    }

    // ------------------------------------------------------------------ 工具

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hex(md.digest(data));
        } catch (Throwable t) {
            return "";
        }
    }

    public static String sha256File(File f) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IOException(e);
        }
        InputStream in = new java.io.FileInputStream(f);
        try {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        } finally {
            in.close();
        }
        return hex(md.digest());
    }

    public static String hex(byte[] b) {
        if (b == null) {
            return "";
        }
        char[] digits = "0123456789abcdef".toCharArray();
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            out[i * 2] = digits[(b[i] >> 4) & 0xf];
            out[i * 2 + 1] = digits[b[i] & 0xf];
        }
        return new String(out);
    }
}
