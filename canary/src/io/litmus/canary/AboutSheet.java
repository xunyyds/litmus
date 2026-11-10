package io.litmus.canary;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import io.litmus.core.BuildInfo;

/**
 * 「设备信息」弹窗：包名 / 版本 / 设备 / native 四行，值一律等宽。
 *
 * <p>外壳与 {@link VectorDetailSheet} 同一套做法（Dialog + 底部对齐 + 透明窗口 + 28dp 顶圆角），
 * 保证两个弹窗观感一致，且不引任何依赖。
 *
 * <p><b>数据来源纪律</b>：全部取自当前这份 report（{@code producer} / {@code app} /
 * {@code device} / {@code facts}），取不到就显示 {@code —}，**绝不编造**。
 * native 那行的两个数是 {@code facts["native.inlineHits"]} / {@code facts["native.gotBad"]}
 * （注意是「命中数 / 坏槽数」，不是扫描总数 —— 契约 §4.5 里没有把 scanned 放进 facts）。
 */
final class AboutSheet {

    private AboutSheet() {
    }

    static void show(Activity activity, JSONObject report) {
        if (activity == null || activity.isFinishing()) {
            return;
        }
        JSONObject producer = report == null ? null : report.optJSONObject("producer");
        JSONObject app = report == null ? null : report.optJSONObject("app");
        JSONObject device = report == null ? null : report.optJSONObject("device");
        JSONObject facts = report == null ? null : report.optJSONObject("facts");

        // ---- 四行的值 ----
        String pkg = app == null ? activity.getPackageName()
                : app.optString("package", activity.getPackageName());

        String version = producer == null ? BuildInfo.version
                : producer.optString("version", BuildInfo.version);
        String flavor = producer == null ? BuildInfo.flavor
                : producer.optString("flavor", BuildInfo.flavor);
        String kit = producer == null ? BuildInfo.kitId
                : producer.optString("kitId", BuildInfo.kitId);
        String versionLine = dash(version) + (flavor == null || flavor.isEmpty() ? "" : " · " + flavor)
                + (kit == null || kit.isEmpty() ? "" : " · kit " + kit);

        String manufacturer = device != null ? device.optString("manufacturer", "") : Build.MANUFACTURER;
        String model = device != null ? device.optString("model", "") : Build.MODEL;
        String release = device != null ? device.optString("release", "") : Build.VERSION.RELEASE;
        int sdk = device != null ? device.optInt("sdk", 0) : Build.VERSION.SDK_INT;
        String abi = facts == null ? "" : facts.optString("native.abi", "");
        if (abi.isEmpty() && Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) {
            // facts 里没有 native.abi（＝native 没加载）时，退到设备真实 ABI；这是观测值，不是编造
            abi = Build.SUPPORTED_ABIS[0];
        }
        StringBuilder devLine = new StringBuilder();
        devLine.append(dash((manufacturer + " " + model).trim()))
                .append(" · Android ").append(dash(release))
                .append(" (API ").append(sdk > 0 ? String.valueOf(sdk) : "—").append(")")
                .append(" · ").append(dash(abi));

        boolean hasNative = producer != null ? producer.optBoolean("hasNative", false) : BuildInfo.hasNative;
        String nativeLine;
        if (hasNative) {
            String hits = facts != null && facts.has("native.inlineHits")
                    ? String.valueOf(facts.optInt("native.inlineHits", 0)) : "—";
            String bad = facts != null && facts.has("native.gotBad")
                    ? String.valueOf(facts.optInt("native.gotBad", 0)) : "—";
            nativeLine = "已加载（inline 命中 " + hits + " / GOT 坏槽 " + bad + "）";
        } else {
            nativeLine = "未加载（native 向量降级 UNKNOWN）";
        }

        // ---- 卡片 ----
        Context dark = new ContextThemeWrapper(activity, android.R.style.Theme_DeviceDefault);
        final Dialog dialog = new Dialog(dark);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        int pad = Ui.dp(activity, 20);
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(Ui.topRounded(Ui.SURFACE_CONTAINER_LOW, Ui.dp(activity, 28)));
        card.setPadding(pad, Ui.dp(activity, 18), pad, Ui.dp(activity, 12));

        TextView title = new TextView(activity);
        title.setText("设备信息");
        title.setTextColor(Ui.ON_SURFACE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        card.addView(title, wrap());

        View divider = new View(activity);
        divider.setBackgroundColor(Ui.OUTLINE_VARIANT);
        LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, Ui.dp(activity, 1)));
        divLp.topMargin = Ui.dp(activity, 14);
        divLp.bottomMargin = Ui.dp(activity, 4);
        card.addView(divider, divLp);

        card.addView(row(activity, "包名", pkg));
        card.addView(row(activity, "版本", versionLine));
        card.addView(row(activity, "设备", devLine.toString()));
        card.addView(row(activity, "native", nativeLine));

        TextView close = new TextView(activity);
        close.setText("关闭");
        close.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        close.setGravity(Gravity.CENTER);
        close.setTextColor(Ui.ON_PRIMARY_CONTAINER);
        close.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        close.setPadding(0, Ui.dp(activity, 12), 0, Ui.dp(activity, 12));
        close.setBackground(Ui.ripple(Ui.PRIMARY_CONTAINER, Ui.dp(activity, 999)));
        close.setClickable(true);
        close.setOnClickListener(v -> dialog.dismiss());
        LinearLayout.LayoutParams closeLp = wrap();
        closeLp.topMargin = Ui.dp(activity, 14);
        card.addView(close, closeLp);

        dialog.setContentView(card);
        Window w = dialog.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            w.setGravity(Gravity.BOTTOM);
            w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            w.setDimAmount(0.62f);
            w.setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.WRAP_CONTENT);
        }
        dialog.show();
        if (w != null) {
            w.setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.WRAP_CONTENT);
        }
        card.setTranslationY(activity.getResources().getDisplayMetrics().heightPixels * 0.30f);
        card.animate().translationY(0f).setDuration(220L).start();
    }

    /** 一行：标签固定宽度 + 等宽值（可换行）。 */
    private static View row(Activity a, String label, String value) {
        LinearLayout row = new LinearLayout(a);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rowLp = wrap();
        rowLp.topMargin = Ui.dp(a, 12);

        TextView l = new TextView(a);
        l.setText(label);
        l.setTextColor(Ui.OUTLINE);
        l.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        l.setLetterSpacing(0.03f);
        row.addView(l, new LinearLayout.LayoutParams(
                Ui.dp(a, 62), ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView v = new TextView(a);
        v.setText(value == null || value.isEmpty() ? "—" : value);
        v.setTextColor(Ui.ON_SURFACE);
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        // 四行的值统一等宽：包名/版本号/设备串/计数对齐后更好扫
        v.setTypeface(Typeface.MONOSPACE);
        v.setLineSpacing(Ui.dp(a, 2), 1f);
        row.addView(v, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.setLayoutParams(rowLp);
        return row;
    }

    private static String dash(String s) {
        return s == null || s.trim().isEmpty() ? "—" : s.trim();
    }

    private static LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }
}
