package io.litmus.core;

import android.util.Log;

/**
 * JNI 桥。契约见 docs/04-契约.md §1.4 / §4.5。
 *
 * <p>加载失败（无 native 库 / 不支持的 ABI）不是错误：上层 {@link LitmusRunner} 会把
 * {@code nat} 置 null，所有依赖 native 的 Probe 自行降级成 UNKNOWN。
 *
 * <p><b>为什么要 catch Throwable</b>：同一个 APK 可能只带部分 ABI 的 .so，也可能被用户
 * 删掉 lib/ 目录。静态块里漏抓就是整个进程崩在类初始化上——比「少 7 条向量」严重得多。
 */
public final class NativeBridge {

    private static final String TAG = "LitmusNative";
    private static final boolean LOADED;

    static {
        boolean ok = false;
        try {
            System.loadLibrary("litmusprobe");
            ok = true;
            Log.i(TAG, "liblitmusprobe loaded");
        } catch (Throwable t) {
            // UnsatisfiedLinkError / ExceptionInInitializerError 都要吞掉，走纯 Java 降级
            Log.w(TAG, "liblitmusprobe unavailable: " + t);
        }
        LOADED = ok;
    }

    public static boolean isLoaded() {
        return LOADED;
    }

    public static native String version();

    /** 一次性快照，JSON 字符串。见 NativeSnapshot。 */
    public static native String snapshot();

    private NativeBridge() {
    }
}
