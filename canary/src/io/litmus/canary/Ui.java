package io.litmus.canary;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.TypefaceSpan;

import java.util.ArrayList;
import java.util.List;

/**
 * 视觉 token 与重复率极高的小工具。
 *
 * <p>色板严格照抄 docs/07-交互与报告规范.md §5（v0.1 那套 M3 token），**不许另起一套**。
 * 层级只用 surface 色阶表达，不用阴影 —— 这是 M3 去阴影化的做法，也省掉了
 * {@code elevation} 在不同 ROM 上渲染不一致的麻烦。
 */
final class Ui {

    static final int SURFACE = 0xFF141218;
    static final int SURFACE_CONTAINER_LOW = 0xFF1D1B20;
    static final int SURFACE_CONTAINER = 0xFF211F26;
    static final int SURFACE_CONTAINER_HIGH = 0xFF2B2930;
    static final int ON_SURFACE = 0xFFE6E0E9;
    static final int ON_SURFACE_VARIANT = 0xFFCAC4D0;
    static final int OUTLINE = 0xFF938F99;
    static final int OUTLINE_VARIANT = 0xFF49454F;
    static final int PRIMARY = 0xFFD0BCFF;
    static final int PRIMARY_CONTAINER = 0xFF4F378B;
    static final int ON_PRIMARY_CONTAINER = 0xFFEADDFF;

    /** verdict 语义色（规范 §5）。 */
    static final int CLEAN = 0xFFB6F09C;
    static final int SUSPECT = 0xFFF9E2AF;
    static final int TAMPERED = 0xFFFFB4AB;
    static final int UNKNOWN = 0xFF938F99;
    static final int ERROR = 0xFFCF6679;

    static final int RIPPLE = 0x33FFFFFF;

    /** 六类：顺序 = 契约 §2.1，不要按出现顺序排。 */
    static final String[][] CATEGORIES = {
            {"runtime-integrity", "运行时完整性", "rt."},
            {"injection", "注入痕迹", "inj."},
            {"package-integrity", "包完整性", "pkg."},
            {"privilege", "提权面", "priv."},
            {"virtualization", "虚拟化 / 多开", "virt."},
            {"environment", "环境面", "env."},
    };

    /** 环境页只关心这三类（Momo 那个「设备脏不脏」的视角）。 */
    private static final String[] DEVICE_CATEGORIES = {"privilege", "virtualization", "environment"};

    private Ui() {
    }

    // ------------------------------------------------------------------ 度量

    static int dp(Context c, float v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    // ------------------------------------------------------------------ 形状 / 水波纹

    /** 纯圆角底色（无涟漪）。 */
    static GradientDrawable rounded(int fill, float radiusPx) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(radiusPx);
        return d;
    }

    static GradientDrawable roundedStroke(int fill, int stroke, float radiusPx, int strokePx) {
        GradientDrawable d = rounded(fill, radiusPx);
        d.setStroke(strokePx, stroke);
        return d;
    }

    static GradientDrawable topRounded(int fill, float radiusPx) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        // 详情卡只有上面两个角是圆的（底部贴着屏幕边）
        d.setCornerRadii(new float[]{radiusPx, radiusPx, radiusPx, radiusPx, 0f, 0f, 0f, 0f});
        return d;
    }

    static GradientDrawable oval(int fill) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColor(fill);
        return d;
    }

    /** M3 水波纹：一层 ripple + 圆角内容底。radiusPx 给足够大即「胶囊/全圆」（会被夹到半高）。 */
    static Drawable ripple(int fill, float radiusPx) {
        return new RippleDrawable(ColorStateList.valueOf(RIPPLE), rounded(fill, radiusPx), null);
    }

    static Drawable rippleOval(int fill) {
        return new RippleDrawable(ColorStateList.valueOf(RIPPLE), oval(fill), null);
    }

    // ------------------------------------------------------------------ 类别 / verdict

    static String categoryZh(String id) {
        for (String[] def : CATEGORIES) {
            if (def[0].equals(id)) {
                return def[1];
            }
        }
        return id == null ? "" : id;
    }

    static boolean isDeviceCategory(String id) {
        if (id == null) {
            return false;
        }
        for (String c : DEVICE_CATEGORIES) {
            if (c.equals(id)) {
                return true;
            }
        }
        return false;
    }

    /** 类别颜色：用来给「环境页」的分组标题一点区分度（不是 verdict 语义色）。 */
    static int categoryAccent(String id) {
        switch (id == null ? "" : id) {
            case "runtime-integrity":
                return PRIMARY;
            case "injection":
                return TAMPERED;
            case "package-integrity":
                return CLEAN;
            case "privilege":
                return SUSPECT;
            case "virtualization":
                return 0xFF9AD0F5;
            default:
                return OUTLINE;
        }
    }

    static int verdictColor(String verdict) {
        switch (verdict == null ? "" : verdict) {
            case "CLEAN":
                return CLEAN;
            case "SUSPECT":
                return SUSPECT;
            case "TAMPERED":
                return TAMPERED;
            case "ERROR":
                return ERROR;
            case "FLAKY":
                return PRIMARY;
            default:
                return UNKNOWN;
        }
    }

    /** 人话说法；规范 R3 要求不出现裸 verdict 词，所以 UI 里成对使用 {@link #verdictLabel}。 */
    static String verdictZh(String verdict) {
        switch (verdict == null ? "" : verdict) {
            case "CLEAN":
                return "通过";
            case "SUSPECT":
                return "可疑";
            case "TAMPERED":
                return "被坐实";
            case "ERROR":
                return "探针异常";
            case "FLAKY":
                return "采样不一致";
            default:
                return "无法判定";
        }
    }

    static String verdictLabel(String verdict) {
        return verdictZh(verdict) + "（" + verdict + "）";
    }

    /** 类别分色：>=85 绿 / 60–84 黄 / <60 红。 */
    static int scoreColor(double score) {
        if (score >= 85d) {
            return CLEAN;
        }
        if (score >= 60d) {
            return SUSPECT;
        }
        return TAMPERED;
    }

    static String scoreText(double score) {
        return String.format(java.util.Locale.US, "%.1f", score);
    }

    /** evidence 是「一行给人看的证据」，屏上只留 N 字，完整原文在报告里。 */
    static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        String one = s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
        if (one.length() <= max) {
            return one;
        }
        return one.substring(0, Math.max(0, max - 1)) + "…";
    }

    // ------------------------------------------------------------------ Markdown 行内代码

    /**
     * 把文案里的 Markdown 行内代码（成对反引号）渲染成**等宽**，并去掉反引号本身。
     *
     * <p>为什么需要：{@code schema/vectors.json} 的 zh/plain/bypass 是按 Markdown 写的
     * （`` `rt.tracerpid` ``、`` `openat("/dev/null")` `` 这种），直接 setText 会让用户看到
     * 一堆字面反引号。这里用框架自带的 {@link TypefaceSpan} 做等宽，零第三方依赖；
     * 反引号之间的引号、括号、斜杠都原样保留，只剥掉反引号。
     *
     * <p>容错：反引号不成对时（例如 evidence 被截断），把未闭合的那一段也当等宽，不吞字。
     */
    static CharSequence md(String src) {
        if (src == null || src.isEmpty()) {
            return "";
        }
        if (src.indexOf('`') < 0) {
            return src;
        }
        StringBuilder plain = new StringBuilder(src.length());
        List<int[]> spans = new ArrayList<>();
        int open = -1;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '`') {
                if (open < 0) {
                    open = plain.length();
                } else {
                    if (plain.length() > open) {
                        spans.add(new int[]{open, plain.length()});
                    }
                    open = -1;
                }
                continue;
            }
            plain.append(c);
        }
        if (open >= 0 && plain.length() > open) {
            spans.add(new int[]{open, plain.length()});
        }
        SpannableStringBuilder sb = new SpannableStringBuilder(plain.toString());
        for (int i = 0; i < spans.size(); i++) {
            int[] r = spans.get(i);
            sb.setSpan(new TypefaceSpan("monospace"), r[0], r[1],
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        return sb;
    }

    /** 去掉反引号但不要样式（复制到剪贴板、写日志用），保证「一行纯文本」。 */
    static String stripMd(String src) {
        if (src == null) {
            return "";
        }
        return src.indexOf('`') < 0 ? src : src.replace("`", "");
    }
}
