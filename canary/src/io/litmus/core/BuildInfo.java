package io.litmus.core;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.InputStream;
import java.util.Properties;

/**
 * 构建期烘进 APK 的期望值。
 *
 * <p>为什么不是代码生成：签名证书 SHA-256 在**构建前**就已知（签名密钥固定），
 * 所以可以烘进去；而 APK 自身的 SHA-256 烘不进自己（签完才产生），那一项交给 CLI 平面判。
 * 见 docs/04-契约.md §4.1 与 docs/02-探针目录.md。
 *
 * <p>资产文件：{@code assets/litmus-build.properties}，由 {@code canary/build.ps1} 生成。
 * 用户重打包时若忘了改它，pkg.* 系列就会报 TAMPERED —— 这正是我们要的。
 */
public final class BuildInfo {

    public static final String ASSET = "litmus-build.properties";

    public static volatile boolean inited = false;
    public static String version = "0.0.0-unknown";
    public static String flavor = "unknown";
    public static String buildUtc = "";
    public static String kitId = "";
    public static boolean hasNative = false;

    /** 原始（未过签）证书 SHA-256：GET_SIGNING_CERTIFICATES 路径的期望值。 */
    public static String expectedCertSha256 = "";
    /** 旧 flags（GET_SIGNATURES）路径的期望值：轮换包里是 lineage 最老的那张证书。 */
    public static String expectedLegacyCertSha256 = "";
    /** getSigningCertificateHistory() 的期望集合，JSON 数组字面量。 */
    public static String expectedCertHistoryJson = "[]";
    public static int expectedSignerCount = 1;

    private BuildInfo() {
    }

    public static synchronized void init(Context c) {
        if (inited) {
            return;
        }
        inited = true;
        AssetManager am = c.getApplicationContext().getAssets();
        Properties p = new Properties();
        try {
            InputStream in = am.open(ASSET);
            try {
                p.load(in);
            } finally {
                in.close();
            }
        } catch (Throwable t) {
            Log.w("LitmusBuildInfo", "cannot read " + ASSET + ": " + t);
            return;
        }
        version = p.getProperty("litmus.version", version);
        flavor = p.getProperty("litmus.flavor", flavor);
        buildUtc = p.getProperty("litmus.buildUtc", buildUtc);
        kitId = p.getProperty("litmus.kitId", kitId);
        hasNative = Boolean.parseBoolean(p.getProperty("litmus.hasNative", "false"));
        expectedCertSha256 = p.getProperty("litmus.expectedCertSha256", "");
        expectedLegacyCertSha256 = p.getProperty("litmus.expectedLegacyCertSha256", "");
        expectedCertHistoryJson = p.getProperty("litmus.expectedCertHistory", "[]");
        try {
            expectedSignerCount = Integer.parseInt(p.getProperty("litmus.expectedSignerCount", "1"));
        } catch (Throwable ignored) {
        }
    }
}
