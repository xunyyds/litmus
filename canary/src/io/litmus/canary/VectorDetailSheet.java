package io.litmus.canary;

import android.app.Activity;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import io.litmus.core.VectorDocs;

/**
 * 单条向量的详情卡：从屏幕底部升起的 28dp 圆角卡（规范 §4）。
 *
 * <p>为什么要它：v0.1 只能看到「{@code rt.maps.file_integrity = TAMPERED}」，
 * 但看不出「这意味着什么、要不要管」。三段文案全部来自 {@link VectorDocs}
 * （由 schema/vectors.json 生成），**UI 里一个字都不硬编码** —— 这样 App 与 CLI 报告
 * 说的永远是同一套话。
 *
 * <p>实现用原生 {@link Dialog} + {@code Window.setGravity(BOTTOM)} + 透明窗口背景，
 * 不引任何 BottomSheet 库，只用系统 Dialog。
 */
final class VectorDetailSheet {

    private VectorDetailSheet() {
    }

    static void show(Activity activity, JSONObject signal) {
        if (activity == null || activity.isFinishing() || signal == null) {
            return;
        }
        final String id = signal.optString("id", "?");
        final String verdict = signal.optString("verdict", "UNKNOWN");
        final String category = signal.optString("category", "");
        final String tier = signal.optString("tier", "-");
        final int weight = signal.optInt("weight", 0);
        final String evidence = signal.optString("evidence", "");

        // 对话框自己带主题：Activity 是浅色 DeviceDefault，弹窗必须显式换成深色，
        // 否则 Dialog 的默认背景/文字是浅色，盖在深色卡上很脏。
        Context dark = new ContextThemeWrapper(activity, android.R.style.Theme_DeviceDefault);
        final Dialog dialog = new Dialog(dark);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        int pad = Ui.dp(activity, 20);

        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(Ui.topRounded(Ui.SURFACE_CONTAINER_LOW, Ui.dp(activity, 28)));
        card.setPadding(pad, Ui.dp(activity, 18), pad, Ui.dp(activity, 12));

        // ---- 头：id + verdict 徽章 ----
        LinearLayout head = new LinearLayout(activity);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        TextView idView = new TextView(activity);
        idView.setText(id);
        idView.setTextColor(Ui.ON_SURFACE);
        idView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        idView.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        head.addView(idView, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView badge = new TextView(activity);
        badge.setText(Ui.verdictZh(verdict) + " · " + verdict);
        badge.setTextColor(Ui.verdictColor(verdict));
        badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        badge.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        badge.setLetterSpacing(0.03f);
        int bPadH = Ui.dp(activity, 10);
        int bPadV = Ui.dp(activity, 5);
        badge.setPadding(bPadH, bPadV, bPadH, bPadV);
        badge.setBackground(Ui.rounded(0x1FFFFFFF, Ui.dp(activity, 999)));
        head.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        card.addView(head, wrap());

        TextView meta = new TextView(activity);
        meta.setText(Ui.categoryZh(category) + " · tier " + tier + " · 权重 " + weight);
        meta.setTextColor(Ui.OUTLINE);
        meta.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        meta.setLetterSpacing(0.03f);
        LinearLayout.LayoutParams metaLp = wrap();
        metaLp.topMargin = Ui.dp(activity, 6);
        card.addView(meta, metaLp);

        View divider = new View(activity);
        divider.setBackgroundColor(Ui.OUTLINE_VARIANT);
        LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, Ui.dp(activity, 1)));
        divLp.topMargin = Ui.dp(activity, 14);
        divLp.bottomMargin = Ui.dp(activity, 6);
        card.addView(divider, divLp);

        // ---- 四段正文：判据 / 证据 / 意味着 / 怎么绕过 ----
        LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);

        body.addView(block(activity, "判据", VectorDocs.zh(id), Ui.ON_SURFACE_VARIANT));
        body.addView(block(activity, "证据",
                evidence == null || evidence.trim().isEmpty() ? "（这一轮探针没有给出证据串）" : evidence,
                Ui.ON_SURFACE));
        body.addView(block(activity, "意味着", VectorDocs.plain(id), Ui.ON_SURFACE_VARIANT));
        body.addView(block(activity, "怎么绕过", VectorDocs.bypass(id), Ui.ON_SURFACE_VARIANT));

        // 长文案（bypass 可能几百字）要能滚，但不能让卡片顶到屏幕外
        MaxScroll scroll = new MaxScroll(activity, (int) (activity.getResources()
                .getDisplayMetrics().heightPixels * 0.62f));
        scroll.setVerticalScrollBarEnabled(false);
        scroll.addView(body);
        card.addView(scroll, wrap());

        // ---- 底部两个按钮 ----
        LinearLayout buttons = new LinearLayout(activity);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams btnRowLp = wrap();
        btnRowLp.topMargin = Ui.dp(activity, 10);

        TextView copy = action(activity, "复制这一条", true);
        copy.setOnClickListener(v -> {
            // I9：剪贴板必须是 `id verdict evidence` 单行（反引号也剥掉，方便贴进报告）
            String line = id + " " + verdict + " " + Ui.stripMd(oneLine(evidence));
            try {
                ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(ClipData.newPlainText("litmus-signal", line));
                    Toast.makeText(activity, "已复制这一条：" + Ui.clip(line, 40),
                            Toast.LENGTH_SHORT).show();
                }
            } catch (Throwable t) {
                Toast.makeText(activity, "复制失败：" + t, Toast.LENGTH_SHORT).show();
            }
            dialog.dismiss();
        });
        LinearLayout.LayoutParams copyLp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        copyLp.rightMargin = Ui.dp(activity, 10);
        buttons.addView(copy, copyLp);

        TextView close = action(activity, "关闭", false);
        close.setOnClickListener(v -> dialog.dismiss());
        buttons.addView(close, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(buttons, btnRowLp);

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
            // Dialog 的 setLayout 要在 show() 之后才吃到 window，这里再设一次保证满宽贴底
            w.setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.WRAP_CONTENT);
        }

        // 「从底部升起」：先偏移 30% 屏高，再 220ms 拉回原位（纯 View 动画，无依赖）
        card.setTranslationY(activity.getResources().getDisplayMetrics().heightPixels * 0.30f);
        card.animate().translationY(0f).setDuration(220L).start();
    }

    /** evidence 只留一行（换行会让剪贴板里的一行契约破掉）。 */
    private static String oneLine(String s) {
        if (s == null) {
            return "";
        }
        return s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
    }

    /** 「标签 + 值」一行：标签固定宽度对齐，长文本自动换行。 */
    private static View block(Activity a, String label, String value, int valueColor) {
        LinearLayout row = new LinearLayout(a);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rowLp = wrap();
        rowLp.topMargin = Ui.dp(a, 10);

        TextView l = new TextView(a);
        l.setText(label);
        l.setTextColor(Ui.OUTLINE);
        l.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        l.setLetterSpacing(0.03f);
        row.addView(l, new LinearLayout.LayoutParams(
                Ui.dp(a, 62), ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView v = new TextView(a);
        // 三段文案与证据都来自 Markdown 语料（schema/vectors.json），这里统一走 Ui.md()
        // 把成对反引号渲染成等宽，避免用户看到字面 ` 字符
        v.setText(Ui.md(value == null || value.isEmpty() ? "—" : value));
        v.setTextColor(valueColor);
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        v.setLineSpacing(Ui.dp(a, 2), 1f);
        v.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        row.addView(v, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.setLayoutParams(rowLp);
        return row;
    }

    private static TextView action(Activity a, String text, boolean primary) {
        TextView b = new TextView(a);
        b.setText(text);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        b.setGravity(Gravity.CENTER);
        b.setPadding(0, Ui.dp(a, 12), 0, Ui.dp(a, 12));
        if (primary) {
            b.setTextColor(Ui.ON_PRIMARY_CONTAINER);
            b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
            b.setBackground(Ui.ripple(Ui.PRIMARY_CONTAINER, Ui.dp(a, 999)));
        } else {
            b.setTextColor(Ui.ON_SURFACE_VARIANT);
            b.setBackground(Ui.ripple(0x00000000, Ui.dp(a, 999)));
        }
        b.setClickable(true);
        b.setFocusable(true);
        return b;
    }

    private static LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    /** 高度上限受控的 ScrollView：Dialog 是 WRAP_CONTENT，长文案不能把卡片顶出屏幕。 */
    private static final class MaxScroll extends ScrollView {
        private final int maxHeight;

        MaxScroll(Activity a, int maxHeight) {
            super(a);
            this.maxHeight = maxHeight;
        }

        @Override
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int size = MeasureSpec.getSize(heightMeasureSpec);
            int mode = MeasureSpec.getMode(heightMeasureSpec);
            if (mode == MeasureSpec.UNSPECIFIED || size > maxHeight) {
                heightMeasureSpec = MeasureSpec.makeMeasureSpec(maxHeight, MeasureSpec.AT_MOST);
            }
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        }
    }
}
