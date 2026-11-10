package io.litmus.canary;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.litmus.core.LitmusRunner;
import io.litmus.core.BuildInfo;

/**
 * 记分板（v0.2 交互版）：TopBar + Hero + 历史 + Segmented 三页 + FAB + 详情卡。
 *
 * <p>信息架构见 docs/07-交互与报告规范.md §2，验收指标 I1–I10 见 §3。
 *
 * <p>几条实现约束（都是踩过的坑）：
 * <ul>
 *   <li><b>零第三方依赖</b>：只有 android.jar 原生控件，不引任何 UI 支持库。M3 观感全靠原生 View +
 *       自绘 Drawable；分层只用 surface 色阶，不用阴影。</li>
 *   <li><b>不写 layout xml</b>：没 gradle，aapt2 报错只给资源 id，定位成本远高于直接 new View。</li>
 *   <li><b>详情文案禁止硬编码</b>：三段说明一律取 {@link io.litmus.core.VectorDocs}，
 *       保证 App 与 CLI 报告是同一套说法。</li>
 *   <li><b>历史不建索引</b>：直接扫 {@code files/litmus/report-*.json}，按 mtime 倒序。</li>
 *   <li><b>搜索框不能被重建</b>：输入时只重建 chips + 列表，否则每次按键都会丢焦点/丢光标。</li>
 * </ul>
 */
public final class MainActivity extends Activity implements LitmusApp.Listener {

    private static final int PAGE_OVERVIEW = 0;
    private static final int PAGE_VECTORS = 1;
    private static final int PAGE_ENV = 2;

    private static final int FILTER_ALL = 0;
    private static final int FILTER_TAMPERED = 1;
    private static final int FILTER_SUSPECT = 2;
    private static final int FILTER_UNJUDGED = 3;

    private Typeface tfMedium;
    private Typeface tfRegular;

    // ---------------------------------------------------------------- 状态
    /** 当前正在展示的报告（可能是刚跑完的，也可能是从历史里点开的）。 */
    private JSONObject report;
    private File reportFile;
    private List<ReportStore.Item> history = new ArrayList<>();
    private int lastReadyGeneration = -1;

    private int page = PAGE_OVERVIEW;
    private int filter = FILTER_ALL;
    /** 从「总览」的类别卡跳过来时预置的类别筛选；null = 不筛。 */
    private String categoryFilter;
    private String query = "";

    // ---------------------------------------------------------------- 视图
    private ScrollView scroll;
    private LinearLayout content;
    private LinearLayout heroBox;
    private LinearLayout historyBox;
    private LinearLayout segBox;
    private LinearLayout overviewBox;
    private LinearLayout vectorsBox;
    private LinearLayout envBox;
    private FrameLayout bodyFrame;
    private ThinProgress topProgress;
    private FabView fab;
    private ImageView refreshIcon;

    private TextView[] segLabels = new TextView[3];
    private EditText search;
    private LinearLayout chipsHost;
    private LinearLayout listBox;

    // ================================================================ 生命周期

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        BuildInfo.init(this);
        tfMedium = Typeface.create("sans-serif-medium", Typeface.NORMAL);
        tfRegular = Typeface.create("sans-serif", Typeface.NORMAL);

        setContentView(buildRoot());
        try {
            getWindow().setStatusBarColor(Ui.SURFACE);
            getWindow().setNavigationBarColor(Ui.SURFACE_CONTAINER);
        } catch (Throwable ignored) {
        }

        LitmusApp.setListener(this);
        syncFromDisk();

        // CLI 兜底触发器：am start … --ez force_run true（App 已在前台时 AMS 会丢弃，
        // 所以真正的兜底是 io.litmus.canary.RUN 广播）
        if (getIntent() != null && getIntent().getBooleanExtra("force_run", false)) {
            LitmusApp.requestRun(this);
            syncFromDisk();
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (intent != null && intent.getBooleanExtra("force_run", false)) {
            LitmusApp.requestRun(this);
            syncFromDisk();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        LitmusApp.setListener(this);
        syncFromDisk();
    }

    @Override
    protected void onDestroy() {
        LitmusApp.setListener(null);
        super.onDestroy();
    }

    /** 后台线程跑完一轮的通知（LitmusApp 保证在主线程回调）。 */
    @Override
    public void onLitmusStateChanged() {
        int ready = LitmusApp.readyGeneration();
        if (ready != lastReadyGeneration) {
            lastReadyGeneration = ready;
            // 有新结果落地 → 自动切回最新，用户不会停在上一次的历史里看旧数字
            reportFile = null;
            report = null;
        }
        syncFromDisk();
    }

    // ================================================================ 数据装填

    /**
     * 从磁盘同步历史并决定展示哪一份。
     *
     * <p>为什么以磁盘为准而不是内存里的 {@link LitmusApp#report()}：历史条目本来就是文件，
     * 两者混用会出现「列表里有 5 条，但当前这条不在列表里」的错位。
     */
    private void syncFromDisk() {
        history = ReportStore.list(this);
        if (reportFile == null || !reportFile.exists()) {
            if (!history.isEmpty()) {
                reportFile = history.get(0).file;
                report = safeRead(reportFile);
            } else {
                // 极端情况：publish 失败但内存里有报告（落盘失败），仍然让 UI 能看
                report = LitmusApp.report();
                reportFile = LitmusApp.reportFile();
            }
        } else if (report == null) {
            report = safeRead(reportFile);
        }
        renderAll();
    }

    private JSONObject safeRead(File f) {
        if (f == null) {
            return LitmusApp.report();
        }
        try {
            return ReportStore.read(f);
        } catch (Throwable t) {
            // 文件被删/写一半 → 退回内存里的最新一份，别让界面空白
            return LitmusApp.report();
        }
    }

    private boolean viewingLatest() {
        return !history.isEmpty() && reportFile != null && history.get(0).file.equals(reportFile);
    }

    private int currentHistoryIndex() {
        for (int i = 0; i < history.size(); i++) {
            if (history.get(i).file.equals(reportFile)) {
                return i;
            }
        }
        return -1;
    }

    private JSONObject summary() {
        return report == null ? null : report.optJSONObject("summary");
    }

    private List<JSONObject> allSignals() {
        List<JSONObject> out = new ArrayList<>();
        JSONArray arr = report == null ? null : report.optJSONArray("signals");
        for (int i = 0; arr != null && i < arr.length(); i++) {
            JSONObject s = arr.optJSONObject(i);
            if (s != null) {
                out.add(s);
            }
        }
        return out;
    }

    // ================================================================ 骨架

    private View buildRoot() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.SURFACE);
        root.setFitsSystemWindows(true);

        root.addView(buildTopBar(), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 52)));

        topProgress = new ThinProgress();
        LinearLayout.LayoutParams progLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(2, Ui.dp(this, 2)));
        topProgress.setVisibility(View.GONE);
        root.addView(topProgress, progLp);

        bodyFrame = new FrameLayout(this);
        scroll = new ScrollView(this);
        scroll.setBackgroundColor(Ui.SURFACE);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setClipToPadding(false);

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(Ui.dp(this, 16), Ui.dp(this, 6), Ui.dp(this, 16), Ui.dp(this, 104));
        scroll.addView(content, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        heroBox = new LinearLayout(this);
        heroBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(heroBox, matchWrap(6));

        historyBox = new LinearLayout(this);
        historyBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(historyBox, matchWrap(12));

        segBox = new LinearLayout(this);
        segBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(segBox, matchWrap(14));

        overviewBox = new LinearLayout(this);
        overviewBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(overviewBox, matchWrap(10));

        vectorsBox = new LinearLayout(this);
        vectorsBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(vectorsBox, matchWrap(10));

        envBox = new LinearLayout(this);
        envBox.setOrientation(LinearLayout.VERTICAL);
        content.addView(envBox, matchWrap(10));

        bodyFrame.addView(scroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        fab = new FabView();
        FrameLayout.LayoutParams fabLp = new FrameLayout.LayoutParams(
                Ui.dp(this, 56), Ui.dp(this, 56), Gravity.END | Gravity.BOTTOM);
        fabLp.setMargins(0, 0, Ui.dp(this, 20), Ui.dp(this, 20));
        bodyFrame.addView(fab, fabLp);

        root.addView(bodyFrame, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private View buildTopBar() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Ui.SURFACE);
        bar.setPadding(Ui.dp(this, 20), 0, Ui.dp(this, 10), 0);

        TextView title = new TextView(this);
        title.setText(getString(R.string.app_name));
        title.setTextColor(Ui.ON_SURFACE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        title.setTypeface(tfMedium);
        title.setLetterSpacing(-0.02f);
        bar.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        refreshIcon = new ImageView(this);
        refreshIcon.setImageDrawable(Glyph.of(Glyph.REFRESH, Ui.ON_SURFACE_VARIANT));
        refreshIcon.setBackground(Ui.rippleOval(0x00000000));
        refreshIcon.setPadding(Ui.dp(this, 10), Ui.dp(this, 10), Ui.dp(this, 10), Ui.dp(this, 10));
        refreshIcon.setOnClickListener(v -> startRun());
        bar.addView(refreshIcon, new LinearLayout.LayoutParams(
                Ui.dp(this, 40), Ui.dp(this, 40)));

        ImageView more = new ImageView(this);
        more.setImageDrawable(Glyph.of(Glyph.MORE, Ui.ON_SURFACE_VARIANT));
        more.setBackground(Ui.rippleOval(0x00000000));
        more.setPadding(Ui.dp(this, 10), Ui.dp(this, 10), Ui.dp(this, 10), Ui.dp(this, 10));
        more.setOnClickListener(this::showOverflowMenu);
        bar.addView(more, new LinearLayout.LayoutParams(
                Ui.dp(this, 40), Ui.dp(this, 40)));
        return bar;
    }

    // ================================================================ 渲染总控

    private void renderAll() {
        renderHero();
        renderHistory();
        renderSegment();
        renderPages();
        renderChrome();
    }

    private void renderChrome() {
        boolean busy = LitmusApp.isRunning();
        topProgress.setVisibility(busy ? View.VISIBLE : View.GONE);
        if (busy) {
            topProgress.start();
        } else {
            topProgress.stop();
        }
        fab.setBusy(busy);
        refreshIcon.setAlpha(busy ? 0.4f : 1f);
        refreshIcon.setEnabled(!busy);
    }

    // ---------------------------------------------------------------- Hero

    private void renderHero() {
        heroBox.removeAllViews();
        LinearLayout card = cardBox(28, Ui.SURFACE_CONTAINER_LOW);
        card.setPadding(Ui.dp(this, 20), Ui.dp(this, 20), Ui.dp(this, 20), Ui.dp(this, 18));
        card.setGravity(Gravity.CENTER_HORIZONTAL);

        JSONObject sum = summary();
        Double score = scoreOf(sum);
        boolean busy = LitmusApp.isRunning();
        String error = LitmusApp.error();

        // 环 + 数字
        FrameLayout ringBox = new FrameLayout(this);
        RingView ring = new RingView();
        ring.setValue(score == null ? -1f : (float) score.doubleValue());
        FrameLayout.LayoutParams ringLp = new FrameLayout.LayoutParams(
                Ui.dp(this, 168), Ui.dp(this, 168), Gravity.CENTER);
        ringBox.addView(ring, ringLp);

        LinearLayout center = new LinearLayout(this);
        center.setOrientation(LinearLayout.VERTICAL);
        center.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams centerLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER);
        ringBox.addView(center, centerLp);

        TextView scoreText = new TextView(this);
        scoreText.setText(score == null ? "—" : String.format(Locale.US, "%.0f", score));
        scoreText.setTextColor(score == null ? Ui.UNKNOWN : Ui.ON_SURFACE);
        scoreText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 64);
        scoreText.setTypeface(tfMedium);
        scoreText.setLetterSpacing(-0.02f);
        scoreText.setGravity(Gravity.CENTER);
        scoreText.setIncludeFontPadding(false);
        center.addView(scoreText, matchWrap(0));

        TextView unit = new TextView(this);
        unit.setText("/100");
        unit.setTextColor(Ui.ON_SURFACE_VARIANT);
        unit.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        unit.setTypeface(tfRegular);
        unit.setLetterSpacing(0.05f);
        unit.setGravity(Gravity.CENTER);
        center.addView(unit, matchWrap(0));

        card.addView(ringBox, new LinearLayout.LayoutParams(
                Ui.dp(this, 168), Ui.dp(this, 168)));

        // 状态句
        TextView headline = new TextView(this);
        headline.setTextColor(score == null ? Ui.UNKNOWN : Ui.ON_SURFACE_VARIANT);
        headline.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        headline.setTypeface(tfRegular);
        headline.setGravity(Gravity.CENTER);
        if (score == null) {
            headline.setText(busy ? "正在检测…" : "无法评分（向量全部 UNKNOWN）");
        } else {
            headline.setText(severityLabel(score) + " · standard");
        }
        card.addView(headline, matchWrap(14));

        // 较上次
        Double delta = deltaOfCurrent();
        if (delta != null) {
            TextView d = new TextView(this);
            String sign = delta > 0.05 ? "+" : (delta < -0.05 ? "−" : "±");
            String arrow = delta > 0.05 ? " ↗" : (delta < -0.05 ? " ↘" : "");
            d.setText("较上次 " + sign + String.format(Locale.US, "%.1f", Math.abs(delta)) + arrow);
            d.setTextColor(Math.abs(delta) <= 0.05 ? Ui.OUTLINE
                    : (delta > 0 ? Ui.CLEAN : Ui.TAMPERED));
            d.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            d.setTypeface(tfMedium);
            d.setGravity(Gravity.CENTER);
            card.addView(d, matchWrap(6));
        } else if (history.size() <= 1 && score != null) {
            TextView d = new TextView(this);
            d.setText("首次检测 · 再跑一次就能看到对比");
            d.setTextColor(Ui.OUTLINE);
            d.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            d.setGravity(Gravity.CENTER);
            card.addView(d, matchWrap(6));
        }

        // 明细
        int total = sum == null ? 0 : sum.optInt("total", 0);
        TextView detail = new TextView(this);
        detail.setText("原始 " + (score == null ? "—" : Ui.scoreText(score))
                + " · 基线 — · " + total + " 条向量");
        detail.setTextColor(Ui.OUTLINE);
        detail.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        detail.setLetterSpacing(0.03f);
        detail.setGravity(Gravity.CENTER);
        card.addView(detail, matchWrap(6));

        // 历史态提示 + 一键回到最新
        if (!viewingLatest() && reportFile != null) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER);
            TextView hint = new TextView(this);
            int idx = currentHistoryIndex();
            String when = idx >= 0 ? ReportStore.relTime(System.currentTimeMillis(), history.get(idx).mtime) : "";
            hint.setText("正在看历史（" + when + "）");
            hint.setTextColor(Ui.SUSPECT);
            hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            row.addView(hint, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            TextView back = new TextView(this);
            back.setText("  回到最新");
            back.setTextColor(Ui.PRIMARY);
            back.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            back.setTypeface(tfMedium);
            back.setPadding(Ui.dp(this, 6), Ui.dp(this, 2), Ui.dp(this, 6), Ui.dp(this, 2));
            back.setOnClickListener(v -> selectLatest());
            row.addView(back, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            card.addView(row, matchWrap(8));
        }

        if (error != null && !error.isEmpty()) {
            TextView err = new TextView(this);
            err.setText("上一次检测失败：" + error);
            err.setTextColor(Ui.ERROR);
            err.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            err.setGravity(Gravity.CENTER);
            card.addView(err, matchWrap(8));
        }

        heroBox.addView(card, matchWrap(0));
    }

    private static String severityLabel(double score) {
        if (score >= 95d) {
            return "未检出篡改";
        }
        if (score >= 85d) {
            return "基本干净";
        }
        if (score >= 60d) {
            return "存在可疑痕迹";
        }
        return "高度可疑 / 已坐实";
    }

    private static Double scoreOf(JSONObject summary) {
        if (summary == null) {
            return null;
        }
        Object raw = summary.opt("score");
        return raw instanceof Number ? ((Number) raw).doubleValue() : null;
    }

    /** 与「更旧的那一次」比；没有更旧的、或两条里有一条没有分数 → null（不显示）。 */
    private Double deltaOfCurrent() {
        int idx = currentHistoryIndex();
        if (idx < 0 || idx + 1 >= history.size()) {
            return null;
        }
        ReportStore.Item cur = history.get(idx);
        ReportStore.Item prev = history.get(idx + 1);
        if (!cur.scored || !prev.scored) {
            return null;
        }
        return cur.score - prev.score;
    }

    // ---------------------------------------------------------------- 历史

    private void renderHistory() {
        historyBox.removeAllViews();
        if (history.isEmpty()) {
            return;
        }
        TextView label = new TextView(this);
        label.setText("最近 " + Math.min(history.size(), ReportStore.MAX_SHOW) + " 次");
        label.setTextColor(Ui.OUTLINE);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        label.setLetterSpacing(0.03f);
        historyBox.addView(label, matchWrap(0));

        HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        hsv.setClipToPadding(false);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(row, new HorizontalScrollView.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        long now = System.currentTimeMillis();
        int count = Math.min(history.size(), ReportStore.MAX_SHOW);
        for (int i = 0; i < count; i++) {
            ReportStore.Item item = history.get(i);
            boolean selected = reportFile != null && reportFile.equals(item.file);
            row.addView(historyCard(item, history.size() > i + 1 ? history.get(i + 1) : null,
                    now, selected));
        }
        historyBox.addView(hsv, matchWrap(8));

        TextView tip = new TextView(this);
        tip.setText("点一下切到那一次 · 长按删除");
        tip.setTextColor(Ui.OUTLINE_VARIANT);
        tip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        historyBox.addView(tip, matchWrap(6));
    }

    private View historyCard(ReportStore.Item item, ReportStore.Item older, long now, boolean selected) {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(Ui.dp(this, 12), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        c.setBackground(selected
                ? Ui.roundedStroke(Ui.PRIMARY_CONTAINER, Ui.PRIMARY, Ui.dp(this, 16), Math.max(1, Ui.dp(this, 1)))
                : Ui.ripple(Ui.SURFACE_CONTAINER_HIGH, Ui.dp(this, 16)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                Ui.dp(this, 96), ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Ui.dp(this, 8);
        c.setLayoutParams(lp);

        TextView score = new TextView(this);
        score.setText(item.scored ? String.format(Locale.US, "%.1f", item.score) : "—");
        score.setTextColor(selected ? Ui.ON_PRIMARY_CONTAINER
                : (item.scored ? Ui.scoreColor(item.score) : Ui.UNKNOWN));
        score.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        score.setTypeface(tfMedium);
        score.setLetterSpacing(-0.02f);
        c.addView(score, matchWrap(0));

        TextView when = new TextView(this);
        when.setText(ReportStore.relTime(now, item.mtime));
        when.setTextColor(selected ? Ui.ON_PRIMARY_CONTAINER : Ui.ON_SURFACE_VARIANT);
        when.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        c.addView(when, matchWrap(1));

        if (item.scored && older != null && older.scored) {
            double delta = item.score - older.score;
            TextView d = new TextView(this);
            String sign = delta > 0.05 ? "+" : (delta < -0.05 ? "−" : "±");
            d.setText(sign + String.format(Locale.US, "%.1f", Math.abs(delta))
                    + (delta > 0.05 ? " ↗" : (delta < -0.05 ? " ↘" : "")));
            d.setTextColor(Math.abs(delta) <= 0.05 ? Ui.OUTLINE
                    : (delta > 0 ? Ui.CLEAN : Ui.TAMPERED));
            d.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            d.setTypeface(tfMedium);
            c.addView(d, matchWrap(1));
        }

        c.setOnClickListener(v -> selectItem(item));
        c.setOnLongClickListener(v -> {
            confirmDelete(item);
            return true;
        });
        c.setClickable(true);
        c.setLongClickable(true);
        return c;
    }

    private void selectItem(ReportStore.Item item) {
        reportFile = item.file;
        report = safeRead(item.file);
        // 切历史时清掉筛选并回到总览：否则用户会停在上一次的关键词/类别里，
        // 看到一个「莫名其妙是空」的列表，误以为那一轮没有向量。
        resetFilters();
        renderAll();
        if (page != PAGE_OVERVIEW) {
            switchPage(PAGE_OVERVIEW, false);
        }
    }

    private void selectLatest() {
        if (history.isEmpty()) {
            reportFile = LitmusApp.reportFile();
            report = LitmusApp.report();
        } else {
            reportFile = history.get(0).file;
            report = safeRead(reportFile);
        }
        resetFilters();
        renderAll();
    }

    /** 清空「类别 / 关键词 / verdict」三个筛选（不动分页）。 */
    private void resetFilters() {
        categoryFilter = null;
        query = "";
        filter = FILTER_ALL;
    }

    private void confirmDelete(final ReportStore.Item item) {
        new AlertDialog.Builder(new ContextThemeWrapper(this, android.R.style.Theme_DeviceDefault))
                .setTitle("删除这条历史？")
                .setMessage(item.runId + " · " + ReportStore.relTime(System.currentTimeMillis(), item.mtime)
                        + "\n只是删掉本机这份报告文件，不影响设备状态。")
                .setPositiveButton("删除", (d, w) -> {
                    boolean ok = ReportStore.delete(item.file);
                    if (!ok) {
                        toast("删除失败：" + item.file.getName());
                    }
                    if (reportFile != null && reportFile.equals(item.file)) {
                        reportFile = null;
                        report = null;
                    }
                    history = ReportStore.list(this);
                    if (reportFile == null && !history.isEmpty()) {
                        reportFile = history.get(0).file;
                        report = safeRead(reportFile);
                    }
                    renderAll();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    // ---------------------------------------------------------------- Segmented

    private void renderSegment() {
        segBox.removeAllViews();
        LinearLayout track = new LinearLayout(this);
        track.setOrientation(LinearLayout.HORIZONTAL);
        track.setBackground(Ui.rounded(Ui.SURFACE_CONTAINER_HIGH, Ui.dp(this, 999)));
        int p = Ui.dp(this, 4);
        track.setPadding(p, p, p, p);

        JSONObject sum = summary();
        int total = sum == null ? 0 : sum.optInt("total", 0);
        int envCount = 0;
        for (JSONObject s : allSignals()) {
            if (Ui.isDeviceCategory(s.optString("category", ""))) {
                envCount++;
            }
        }
        String[] labels = {"总览", "向量 " + total, "环境 " + envCount};
        for (int i = 0; i < 3; i++) {
            final int index = i;
            TextView t = new TextView(this);
            t.setText(labels[i]);
            t.setGravity(Gravity.CENTER);
            t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            t.setTypeface(i == page ? tfMedium : tfRegular);
            t.setTextColor(i == page ? Ui.ON_PRIMARY_CONTAINER : Ui.ON_SURFACE_VARIANT);
            t.setPadding(0, Ui.dp(this, 10), 0, Ui.dp(this, 10));
            t.setBackground(i == page
                    ? Ui.ripple(Ui.PRIMARY_CONTAINER, Ui.dp(this, 999))
                    : Ui.ripple(0x00000000, Ui.dp(this, 999)));
            t.setOnClickListener(v -> switchPage(index, true));
            t.setClickable(true);
            segLabels[i] = t;
            track.addView(t, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
        segBox.addView(track, matchWrap(0));
    }

    private void switchPage(int target, boolean scrollToTop) {
        page = target;
        overviewBox.setVisibility(target == PAGE_OVERVIEW ? View.VISIBLE : View.GONE);
        vectorsBox.setVisibility(target == PAGE_VECTORS ? View.VISIBLE : View.GONE);
        envBox.setVisibility(target == PAGE_ENV ? View.VISIBLE : View.GONE);
        renderSegment();
        if (scrollToTop) {
            scroll.post(() -> scroll.smoothScrollTo(0, Math.max(0, segBox.getTop() - Ui.dp(this, 8))));
        }
    }

    // ---------------------------------------------------------------- 三页

    private void renderPages() {
        renderOverviewPage();
        renderVectorsPage();
        renderEnvPage();
        switchPage(page, false);
    }

    private void renderOverviewPage() {
        overviewBox.removeAllViews();
        JSONObject sum = summary();
        if (sum == null) {
            overviewBox.addView(emptyState(
                    LitmusApp.isRunning() ? "正在跑第一轮检测…" : "还没有报告",
                    LitmusApp.isRunning()
                            ? "45 条向量跑完大概 1 秒，跑完这里会出现六类分数。"
                            : "点右下角的圆形按钮开始一次检测；冷启动时通常已经自动跑过一次。"), matchWrap(4));
            return;
        }

        // 统计胶囊
        HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        hsv.setClipToPadding(false);
        LinearLayout pills = new LinearLayout(this);
        pills.setOrientation(LinearLayout.HORIZONTAL);
        pills.addView(pill("通过", sum.optInt("clean", 0), Ui.CLEAN));
        pills.addView(pill("可疑", sum.optInt("suspect", 0), Ui.SUSPECT));
        pills.addView(pill("篡改", sum.optInt("tampered", 0), Ui.TAMPERED));
        pills.addView(pill("未判", sum.optInt("unknown", 0) + sum.optInt("error", 0)
                + sum.optInt("flaky", 0), Ui.UNKNOWN));
        hsv.addView(pills, new HorizontalScrollView.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        overviewBox.addView(hsv, matchWrap(0));

        // 六张类别卡
        JSONArray cats = sum.optJSONArray("categories");
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCategory(cats, def[0]);
            Double catScore = null;
            if (c != null) {
                Object raw = c.opt("score");
                if (raw instanceof Number) {
                    catScore = ((Number) raw).doubleValue();
                }
            }
            int tampered = c == null ? 0 : c.optInt("tampered", 0);
            int suspect = c == null ? 0 : c.optInt("suspect", 0);
            int total = c == null ? 0 : c.optInt("total", 0);
            overviewBox.addView(categoryCard(def[0], def[1], catScore, tampered, suspect, total),
                    matchWrap(10));
        }

        TextView hint = new TextView(this);
        hint.setText("点任意一张卡片 → 到「向量」页看这一类的每一条");
        hint.setTextColor(Ui.OUTLINE_VARIANT);
        hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        overviewBox.addView(hint, matchWrap(10));
    }

    private View categoryCard(String id, String zh, Double score, int tampered, int suspect, int total) {
        LinearLayout card = cardBox(16, Ui.SURFACE_CONTAINER_LOW);
        card.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        card.setBackground(Ui.ripple(Ui.SURFACE_CONTAINER_LOW, Ui.dp(this, 16)));
        card.setClickable(true);
        card.setOnClickListener(v -> {
            categoryFilter = id;
            filter = FILTER_ALL;
            renderPages();
            switchPage(PAGE_VECTORS, true);
        });

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        TextView name = new TextView(this);
        name.setText(zh);
        name.setTextColor(Ui.ON_SURFACE);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        name.setTypeface(tfMedium);
        head.addView(name, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView scoreView = new TextView(this);
        scoreView.setText(score == null ? "—" : String.format(Locale.US, "%.0f", score));
        scoreView.setTextColor(score == null ? Ui.UNKNOWN : Ui.scoreColor(score));
        scoreView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        scoreView.setTypeface(tfMedium);
        head.addView(scoreView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        card.addView(head, matchWrap(0));

        BarView bar = new BarView();
        bar.setFraction(score == null ? 0f : (float) (score.doubleValue() / 100d));
        bar.setColors(Ui.OUTLINE_VARIANT, score == null ? Ui.UNKNOWN : Ui.scoreColor(score));
        LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(3, Ui.dp(this, 3)));
        barLp.topMargin = Ui.dp(this, 10);
        card.addView(bar, barLp);

        TextView sub = new TextView(this);
        sub.setText("已坐实 " + tampered + " · 可疑 " + suspect + " · 共 " + total);
        sub.setTextColor(Ui.OUTLINE);
        sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        sub.setLetterSpacing(0.03f);
        card.addView(sub, matchWrap(8));
        return card;
    }

    private static JSONObject findCategory(JSONArray cats, String id) {
        for (int i = 0; cats != null && i < cats.length(); i++) {
            JSONObject c = cats.optJSONObject(i);
            if (c != null && id.equals(c.optString("id", ""))) {
                return c;
            }
        }
        return null;
    }

    private View pill(String label, int count, int dotColor) {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.HORIZONTAL);
        p.setGravity(Gravity.CENTER_VERTICAL);
        p.setPadding(Ui.dp(this, 12), Ui.dp(this, 8), Ui.dp(this, 14), Ui.dp(this, 8));
        p.setBackground(Ui.rounded(Ui.SURFACE_CONTAINER_HIGH, Ui.dp(this, 999)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Ui.dp(this, 8);
        p.setLayoutParams(lp);

        View dot = new View(this);
        dot.setBackground(Ui.oval(dotColor));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(
                Ui.dp(this, 8), Ui.dp(this, 8));
        dotLp.rightMargin = Ui.dp(this, 8);
        p.addView(dot, dotLp);

        TextView t = new TextView(this);
        t.setText(label + " " + count);
        t.setTextColor(Ui.ON_SURFACE_VARIANT);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        p.addView(t, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return p;
    }

    // ---------------------------------------------------------------- 向量页

    private void renderVectorsPage() {
        vectorsBox.removeAllViews();
        chipsHost = null;
        listBox = null;
        search = null;

        if (report == null) {
            vectorsBox.addView(emptyState(
                    LitmusApp.isRunning() ? "正在跑第一轮检测…" : "还没有报告",
                    LitmusApp.isRunning()
                            ? "跑完这里会出现 45 条向量，可以按状态筛选、按 id 搜索。"
                            : "点右下角按钮跑一次，就能看到每条向量的判据和证据。"), matchWrap(4));
            return;
        }

        // chips
        HorizontalScrollView chipScroll = new HorizontalScrollView(this);
        chipScroll.setHorizontalScrollBarEnabled(false);
        chipScroll.setClipToPadding(false);
        chipsHost = new LinearLayout(this);
        chipsHost.setOrientation(LinearLayout.HORIZONTAL);
        chipScroll.addView(chipsHost, new HorizontalScrollView.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        vectorsBox.addView(chipScroll, matchWrap(0));

        // 搜索框（单独一行，输入时**不重建它**，否则每次按键都丢焦点）
        vectorsBox.addView(buildSearchField(), matchWrap(8));

        // 列表
        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        vectorsBox.addView(listBox, matchWrap(10));

        rebuildChipsAndList();
    }

    private View buildSearchField() {
        EditText e = new EditText(this);
        e.setHint("搜索向量 id，例如 frida / maps / sig");
        e.setHintTextColor(Ui.OUTLINE);
        e.setTextColor(Ui.ON_SURFACE);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_TEXT);
        e.setBackground(Ui.rounded(Ui.SURFACE_CONTAINER_HIGH, Ui.dp(this, 14)));
        int ph = Ui.dp(this, 11);
        e.setPadding(Ui.dp(this, 12), ph, Ui.dp(this, 12), ph);
        e.setText(query);
        try {
            Glyph g = Glyph.of(Glyph.SEARCH, Ui.OUTLINE);
            g.setBounds(0, 0, Ui.dp(this, 16), Ui.dp(this, 16));
            e.setCompoundDrawablesRelative(g, null, null, null);
            e.setCompoundDrawablePadding(Ui.dp(this, 8));
        } catch (Throwable ignored) {
        }
        e.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                query = s == null ? "" : s.toString();
                rebuildChipsAndList();
            }
        });
        search = e;
        return e;
    }

    /** 只重建 chips + 列表（搜索框与页面骨架保持不动）。 */
    private void rebuildChipsAndList() {
        if (chipsHost != null) {
            chipsHost.removeAllViews();
            List<JSONObject> base = matchedSignals(true);
            // 类别 chip 必须放**第一个**：chips 行是横向滚动的，放末尾会被挤出屏幕，
            // 用户从类别卡跳过来后既看不到当前筛了什么、也找不到「✕」取消。
            if (categoryFilter != null) {
                chipsHost.addView(categoryChip());
            }
            chipsHost.addView(filterChip("全部", base.size(), FILTER_ALL));
            chipsHost.addView(filterChip("篡改", countVerdict(base, "TAMPERED"), FILTER_TAMPERED));
            chipsHost.addView(filterChip("可疑", countVerdict(base, "SUSPECT"), FILTER_SUSPECT));
            chipsHost.addView(filterChip("未判", countUnjudged(base), FILTER_UNJUDGED));
        }
        if (listBox != null) {
            listBox.removeAllViews();
            List<JSONObject> list = matchedSignals(true);
            if (filter != FILTER_ALL) {
                List<JSONObject> kept = new ArrayList<>();
                for (JSONObject s : list) {
                    if (matchesFilter(s, filter)) {
                        kept.add(s);
                    }
                }
                list = kept;
            }
            if (list.isEmpty()) {
                String why;
                if (!query.trim().isEmpty()) {
                    why = "没有 id 含「" + Ui.clip(query.trim(), 20) + "」的向量。换个关键词，或点「全部」。";
                } else if (categoryFilter != null) {
                    why = "「" + Ui.categoryZh(categoryFilter) + "」这一类没有符合当前筛选的向量。";
                } else {
                    why = "这一类在这个筛选下没有向量。";
                }
                listBox.addView(emptyState("没有匹配的向量", why), matchWrap(6));
                return;
            }
            // 按类别分组（契约 §2.1 顺序）
            for (String[] def : Ui.CATEGORIES) {
                List<JSONObject> group = new ArrayList<>();
                for (JSONObject s : list) {
                    if (def[0].equals(s.optString("category", ""))) {
                        group.add(s);
                    }
                }
                if (group.isEmpty()) {
                    continue;
                }
                listBox.addView(groupHeader(def[0], def[1], group), matchWrap(12));
                for (JSONObject s : group) {
                    listBox.addView(signalRow(s, false), matchWrap(0));
                }
            }
        }
    }

    private View filterChip(String label, int count, final int which) {
        boolean on = filter == which;
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.HORIZONTAL);
        c.setGravity(Gravity.CENTER_VERTICAL);
        c.setPadding(Ui.dp(this, 12), Ui.dp(this, 7), Ui.dp(this, 12), Ui.dp(this, 7));
        c.setBackground(on
                ? Ui.ripple(Ui.PRIMARY_CONTAINER, Ui.dp(this, 999))
                : Ui.ripple(Ui.SURFACE_CONTAINER_HIGH, Ui.dp(this, 999)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Ui.dp(this, 8);
        c.setLayoutParams(lp);

        TextView t = new TextView(this);
        t.setText(label + " " + count);
        t.setTextColor(on ? Ui.ON_PRIMARY_CONTAINER : Ui.ON_SURFACE_VARIANT);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setTypeface(on ? tfMedium : tfRegular);
        c.addView(t, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        c.setClickable(true);
        c.setOnClickListener(v -> {
            filter = which;
            rebuildChipsAndList();
        });
        return c;
    }

    private View categoryChip() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.HORIZONTAL);
        c.setGravity(Gravity.CENTER_VERTICAL);
        c.setPadding(Ui.dp(this, 12), Ui.dp(this, 7), Ui.dp(this, 12), Ui.dp(this, 7));
        c.setBackground(Ui.ripple(0x00000000, Ui.dp(this, 999)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = Ui.dp(this, 8);
        c.setLayoutParams(lp);

        TextView t = new TextView(this);
        t.setText(Ui.categoryZh(categoryFilter) + "  ✕");
        t.setTextColor(Ui.PRIMARY);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setTypeface(tfMedium);
        c.addView(t, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        c.setClickable(true);
        c.setOnClickListener(v -> {
            categoryFilter = null;
            rebuildChipsAndList();
        });
        return c;
    }

    /** 向量页/环境页共用的「搜 + 类别」匹配（不含 verdict 筛选）。 */
    private List<JSONObject> matchedSignals(boolean vectorsPage) {
        List<JSONObject> out = new ArrayList<>();
        String q = query == null ? "" : query.trim().toLowerCase(Locale.CHINA);
        for (JSONObject s : allSignals()) {
            String id = s.optString("id", "");
            String cat = s.optString("category", "");
            if (vectorsPage) {
                if (categoryFilter != null && !categoryFilter.equals(cat)) {
                    continue;
                }
            } else if (!Ui.isDeviceCategory(cat)) {
                continue;
            }
            if (!q.isEmpty() && !id.toLowerCase(Locale.CHINA).contains(q)) {
                continue;
            }
            out.add(s);
        }
        return out;
    }

    private static boolean matchesFilter(JSONObject s, int which) {
        String v = s.optString("verdict", "UNKNOWN");
        switch (which) {
            case FILTER_TAMPERED:
                return "TAMPERED".equals(v);
            case FILTER_SUSPECT:
                return "SUSPECT".equals(v);
            case FILTER_UNJUDGED:
                return "UNKNOWN".equals(v) || "ERROR".equals(v) || "FLAKY".equals(v);
            default:
                return true;
        }
    }

    private static int countVerdict(List<JSONObject> list, String verdict) {
        int n = 0;
        for (JSONObject s : list) {
            if (verdict.equals(s.optString("verdict", ""))) {
                n++;
            }
        }
        return n;
    }

    private static int countUnjudged(List<JSONObject> list) {
        int n = 0;
        for (JSONObject s : list) {
            String v = s.optString("verdict", "");
            if ("UNKNOWN".equals(v) || "ERROR".equals(v) || "FLAKY".equals(v)) {
                n++;
            }
        }
        return n;
    }

    private View groupHeader(String category, String zh, List<JSONObject> group) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

        View accent = new View(this);
        accent.setBackground(Ui.rounded(Ui.categoryAccent(category), Math.max(2, Ui.dp(this, 2))));
        LinearLayout.LayoutParams accentLp = new LinearLayout.LayoutParams(
                Math.max(3, Ui.dp(this, 3)), Ui.dp(this, 12));
        accentLp.rightMargin = Ui.dp(this, 8);
        row.addView(accent, accentLp);

        TextView t = new TextView(this);
        t.setText(zh);
        t.setTextColor(Ui.ON_SURFACE_VARIANT);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        t.setTypeface(tfMedium);
        t.setLetterSpacing(0.03f);
        row.addView(t, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView count = new TextView(this);
        count.setText(group.size() + " 条");
        count.setTextColor(Ui.OUTLINE);
        count.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        row.addView(count, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return row;
    }

    /** 一条向量：状态点 + id + verdict 徽章 + 截断 evidence；点任意位置开详情卡（I2）。 */
    private View signalRow(final JSONObject s, boolean devicePage) {
        String verdict = s.optString("verdict", "UNKNOWN");

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(Ui.dp(this, 6), Ui.dp(this, 9), Ui.dp(this, 6), Ui.dp(this, 9));
        row.setBackground(Ui.ripple(0x00000000, Ui.dp(this, 12)));
        row.setClickable(true);

        LinearLayout line1 = new LinearLayout(this);
        line1.setOrientation(LinearLayout.HORIZONTAL);
        line1.setGravity(Gravity.CENTER_VERTICAL);

        View dot = new View(this);
        dot.setBackground(Ui.oval(Ui.verdictColor(verdict)));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(
                Ui.dp(this, 8), Ui.dp(this, 8));
        dotLp.rightMargin = Ui.dp(this, 9);
        line1.addView(dot, dotLp);

        TextView id = new TextView(this);
        id.setText(s.optString("id", "?"));
        id.setTextColor(Ui.ON_SURFACE);
        id.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        id.setTypeface(tfRegular);
        line1.addView(id, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView badge = new TextView(this);
        badge.setText(Ui.verdictZh(verdict));
        badge.setTextColor(Ui.verdictColor(verdict));
        badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        badge.setTypeface(tfMedium);
        badge.setLetterSpacing(0.03f);
        line1.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        row.addView(line1, matchWrap(0));

        TextView ev = new TextView(this);
        // evidence 也可能带 Markdown 行内代码（CLI 会输出 `cli-expect-mismatch` 这种），
        // 统一走 Ui.md()：成对反引号 → 等宽，反引号本身不显示
        ev.setText(Ui.md(Ui.clip(s.optString("evidence", ""), 60)));
        ev.setTextColor(Ui.ON_SURFACE_VARIANT);
        ev.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        LinearLayout.LayoutParams evLp = matchWrap(2);
        evLp.leftMargin = Ui.dp(this, 17);
        row.addView(ev, evLp);

        row.setOnClickListener(v -> VectorDetailSheet.show(MainActivity.this, s));
        return row;
    }

    // ---------------------------------------------------------------- 环境页

    private void renderEnvPage() {
        envBox.removeAllViews();
        if (report == null) {
            envBox.addView(emptyState(
                    LitmusApp.isRunning() ? "正在跑第一轮检测…" : "还没有报告",
                    "跑完这里会把「提权面 / 虚拟化 / 环境面」单独列出来——就是 Momo 那个「设备脏不脏」的视角。"),
                    matchWrap(4));
            return;
        }
        List<JSONObject> env = matchedSignals(false);
        int tampered = countVerdict(env, "TAMPERED");
        int suspect = countVerdict(env, "SUSPECT");
        int clean = countVerdict(env, "CLEAN");
        int unjudged = countUnjudged(env);

        LinearLayout head = cardBox(16, Ui.SURFACE_CONTAINER_LOW);
        head.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 14));
        TextView title = new TextView(this);
        title.setText("这台设备有多脏");
        title.setTextColor(Ui.ON_SURFACE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(tfMedium);
        head.addView(title, matchWrap(0));

        TextView body = new TextView(this);
        body.setText("共 " + env.size() + " 条：被坐实 " + tampered + " · 可疑 " + suspect
                + " · 通过 " + clean + " · 未判 " + unjudged);
        body.setTextColor(Ui.ON_SURFACE_VARIANT);
        body.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        head.addView(body, matchWrap(6));

        TextView note = new TextView(this);
        note.setText(tampered == 0
                ? "没有一条被坐实。若这里是模拟器或带了 root 模块，说明这几条向量对本机不敏感——"
                + "它们只出「可疑」，最终判断交给 CLI 的基线对比。"
                : "有 " + tampered + " 条被坐实：先看它在「向量」页的同名条目，再决定要不要换台干净机重测。");
        note.setTextColor(Ui.OUTLINE);
        note.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        note.setLineSpacing(Ui.dp(this, 2), 1f);
        head.addView(note, matchWrap(8));
        envBox.addView(head, matchWrap(3));

        for (String[] def : new String[][]{
                {"privilege", "提权面"}, {"virtualization", "虚拟化 / 多开"}, {"environment", "环境面"}}) {
            List<JSONObject> group = new ArrayList<>();
            for (JSONObject s : env) {
                if (def[0].equals(s.optString("category", ""))) {
                    group.add(s);
                }
            }
            if (group.isEmpty()) {
                continue;
            }
            envBox.addView(groupHeader(def[0], def[1], group), matchWrap(14));
            for (JSONObject s : group) {
                envBox.addView(signalRow(s, true), matchWrap(0));
            }
        }
        if (env.isEmpty()) {
            envBox.addView(emptyState("环境面没有命中任何向量",
                    "这通常是最好的结果：设备面（提权/虚拟化/环境）一条都没露痕迹。"), matchWrap(10));
        }
    }

    // ---------------------------------------------------------------- 空态

    private View emptyState(String title, String body) {
        LinearLayout box = cardBox(16, Ui.SURFACE_CONTAINER_LOW);
        box.setPadding(Ui.dp(this, 18), Ui.dp(this, 18), Ui.dp(this, 18), Ui.dp(this, 18));
        TextView t = new TextView(this);
        t.setText(title);
        t.setTextColor(Ui.ON_SURFACE);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        t.setTypeface(tfMedium);
        box.addView(t, matchWrap(0));
        TextView b = new TextView(this);
        b.setText(body);
        b.setTextColor(Ui.ON_SURFACE_VARIANT);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        b.setLineSpacing(Ui.dp(this, 3), 1f);
        box.addView(b, matchWrap(6));
        return box;
    }

    // ================================================================ 动作

    private void startRun() {
        if (LitmusApp.isRunning()) {
            return;
        }
        LitmusApp.requestRun(this);
        renderChrome();
    }

    private void showOverflowMenu(View anchor) {
        Context dark = new ContextThemeWrapper(this, android.R.style.Theme_DeviceDefault);
        PopupMenu menu = new PopupMenu(dark, anchor);
        // 顺序：设备信息 / HTML 两项 / 分享摘要 / 复制 JSON / 导出文件
        menu.getMenu().add(0, 1, 1, "设备信息");
        menu.getMenu().add(0, 2, 2, "查看 HTML 报告");
        menu.getMenu().add(0, 3, 3, "导出 HTML 报告");
        menu.getMenu().add(0, 4, 4, "分享摘要");
        menu.getMenu().add(0, 5, 5, "复制 JSON");
        menu.getMenu().add(0, 6, 6, "导出文件");
        menu.setOnMenuItemClickListener(item -> {
            switch (item.getItemId()) {
                case 1:
                    AboutSheet.show(this, report);
                    return true;
                case 2:
                    openHtmlReport();
                    return true;
                case 3:
                    exportHtmlReport();
                    return true;
                case 4:
                    shareReport();
                    return true;
                case 5:
                    copyJson();
                    return true;
                case 6:
                    exportFile();
                    return true;
                default:
                    return false;
            }
        });
        menu.show();
    }

    // ---------------------------------------------------------------- HTML 报告

    /**
     * 生成（或复用）本次报告的 HTML，落在 {@code getExternalFilesDir(null)/litmus/report-<runId>.html}。
     *
     * <p>「查看」和「导出」写同一份文件：手机上两份同名产物只会让人不知道该看哪份；
     * 而 files/litmus 本来就是本应用的产物目录，adb pull 得出来。
     */
    private File writeHtmlReport() throws Exception {
        File base = getExternalFilesDir(null);
        if (base == null) {
            base = getFilesDir();
        }
        File dir = new File(base, "litmus");
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File out = new File(dir, "report-" + HtmlReport.runId(report) + ".html");
        ReportViewer.writeUtf8(out, HtmlReport.render(this, report));
        return out;
    }

    /** 菜单「查看 HTML 报告」：生成后交给 {@link ReportViewer}；起不来就内嵌看（并明说）。 */
    private void openHtmlReport() {
        if (report == null) {
            toast(LitmusApp.isRunning() ? "还在检测中，稍等" : "还没有报告可看");
            return;
        }
        File html;
        try {
            html = writeHtmlReport();
        } catch (Throwable t) {
            toast("生成 HTML 失败：" + t);
            return;
        }
        Intent intent = new Intent(this, ReportViewer.class);
        intent.putExtra(ReportViewer.EXTRA_HTML, html.getAbsolutePath());
        try {
            startActivity(intent);
        } catch (Throwable t) {
            // 清单被动手改过 / 组件被系统禁用时才会走到这里 —— 明确告知，别让用户以为按钮坏了
            toast("用内嵌视图打开");
            ReportViewer.showInline(this, html);
        }
    }

    /** 菜单「导出 HTML 报告」：写盘 + toast 完整路径（与「查看」同一路径）。 */
    private void exportHtmlReport() {
        if (report == null) {
            toast(LitmusApp.isRunning() ? "还在检测中，稍等" : "还没有报告可导出");
            return;
        }
        try {
            File html = writeHtmlReport();
            toast("已导出：" + html.getAbsolutePath());
        } catch (Throwable t) {
            toast("导出失败：" + t);
        }
    }

    private String currentJson() {
        if (report == null) {
            return "";
        }
        try {
            return report.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    private void copyJson() {
        String json = currentJson();
        if (json.isEmpty()) {
            toast(LitmusApp.isRunning() ? "还在检测中，稍等" : "还没有报告可复制");
            return;
        }
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm == null) {
                toast("剪贴板不可用");
                return;
            }
            cm.setPrimaryClip(ClipData.newPlainText("litmus-report", json));
            toast("已复制整份报告 JSON（" + json.getBytes("UTF-8").length + " 字节）");
        } catch (Throwable t) {
            toast("复制失败：" + t);
        }
    }

    private void exportFile() {
        if (report == null) {
            toast(LitmusApp.isRunning() ? "还在检测中，稍等" : "还没有报告可导出");
            return;
        }
        File f = reportFile;
        if (f == null || !f.exists()) {
            try {
                File base = getExternalFilesDir(null);
                if (base == null) {
                    base = getFilesDir();
                }
                File dir = new File(base, "litmus");
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
                JSONObject run = report.optJSONObject("run");
                String runId = run == null ? "unknown" : run.optString("id", "unknown");
                f = new File(dir, "report-" + runId + ".json");
                FileOutputStream fos = new FileOutputStream(f);
                try {
                    fos.write(currentJson().getBytes("UTF-8"));
                } finally {
                    fos.close();
                }
            } catch (Throwable t) {
                toast("导出失败：" + t);
                return;
            }
        }
        toast("已导出：" + f.getAbsolutePath());
    }

    /** 分享用 ACTION_SEND + EXTRA_TEXT：不走 FileProvider（没有支持库可用）。 */
    private void shareReport() {
        String json = currentJson();
        if (json.isEmpty()) {
            toast(LitmusApp.isRunning() ? "还在检测中，稍等" : "还没有报告可分享");
            return;
        }
        try {
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            JSONObject run = report.optJSONObject("run");
            String runId = run == null ? "" : run.optString("id", "");
            send.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.app_name) + " 报告 " + runId);
            send.putExtra(Intent.EXTRA_TEXT, json);
            startActivity(Intent.createChooser(send, "分享" + getString(R.string.app_name) + "报告"));
        } catch (Throwable t) {
            toast("没有可用的分享目标：" + t);
        }
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }

    // ================================================================ 小工具

    private LinearLayout cardBox(int radiusDp, int color) {
        LinearLayout v = new LinearLayout(this);
        v.setOrientation(LinearLayout.VERTICAL);
        v.setBackground(Ui.rounded(color, Ui.dp(this, radiusDp)));
        return v;
    }

    private LinearLayout.LayoutParams matchWrap(int topDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Ui.dp(this, topDp);
        return lp;
    }

    // ================================================================ 自绘组件

    /** 分数环：底环 outlineVariant + 进度 primary，12dp 线宽、圆头。 */
    private final class RingView extends View {
        private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint progressPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF oval = new RectF();
        private float value = -1f;

        RingView() {
            super(MainActivity.this);
            float stroke = Ui.dp(MainActivity.this, 12);
            trackPaint.setStyle(Paint.Style.STROKE);
            trackPaint.setStrokeWidth(stroke);
            trackPaint.setStrokeCap(Paint.Cap.ROUND);
            trackPaint.setColor(Ui.OUTLINE_VARIANT);
            progressPaint.setStyle(Paint.Style.STROKE);
            progressPaint.setStrokeWidth(stroke);
            progressPaint.setStrokeCap(Paint.Cap.ROUND);
            progressPaint.setColor(Ui.PRIMARY);
        }

        void setValue(float v) {
            this.value = v;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float stroke = trackPaint.getStrokeWidth();
            float inset = stroke / 2f;
            oval.set(inset, inset, getWidth() - inset, getHeight() - inset);
            canvas.drawArc(oval, 0f, 360f, false, trackPaint);
            if (value > 0f) {
                canvas.drawArc(oval, -90f, 360f * Math.min(100f, value) / 100f, false, progressPaint);
            }
        }
    }

    /** 3dp 细进度条（类别卡）。 */
    private final class BarView extends View {
        private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF rect = new RectF();
        private float fraction;

        BarView() {
            super(MainActivity.this);
            trackPaint.setColor(Ui.OUTLINE_VARIANT);
            fillPaint.setColor(Ui.PRIMARY);
        }

        void setColors(int track, int fill) {
            trackPaint.setColor(track);
            fillPaint.setColor(fill);
            invalidate();
        }

        void setFraction(float f) {
            this.fraction = Math.max(0f, Math.min(1f, f));
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float r = getHeight() / 2f;
            rect.set(0f, 0f, getWidth(), getHeight());
            canvas.drawRoundRect(rect, r, r, trackPaint);
            if (fraction > 0f) {
                rect.set(0f, 0f, Math.max(getHeight(), getWidth() * fraction), getHeight());
                canvas.drawRoundRect(rect, r, r, fillPaint);
            }
        }
    }

    /** 顶部 2dp 不确定进度条（检测中）。自绘，避免依赖主题里的 ProgressBar 样式。 */
    private final class ThinProgress extends View {
        private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint barPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final android.animation.ValueAnimator animator;
        private float t;

        ThinProgress() {
            super(MainActivity.this);
            trackPaint.setColor(Ui.SURFACE_CONTAINER_HIGH);
            barPaint.setColor(Ui.PRIMARY);
            animator = android.animation.ValueAnimator.ofFloat(0f, 1f);
            animator.setDuration(1100L);
            animator.setRepeatCount(android.animation.ValueAnimator.INFINITE);
            animator.setInterpolator(new LinearInterpolator());
            animator.addUpdateListener(a -> {
                t = (float) a.getAnimatedValue();
                invalidate();
            });
        }

        void start() {
            if (!animator.isStarted()) {
                animator.start();
            }
        }

        void stop() {
            animator.cancel();
            t = 0f;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            canvas.drawRect(0, 0, getWidth(), getHeight(), trackPaint);
            float seg = getWidth() * 0.34f;
            float x = (getWidth() + seg) * t - seg;
            canvas.drawRect(x, 0, x + seg, getHeight(), barPaint);
        }
    }

    /** FAB：56dp 圆形，检测中变转圈 + 禁用（I5）。 */
    private final class FabView extends FrameLayout {
        private final ImageView icon;
        private final SpinnerArc arc;
        private boolean busy;

        FabView() {
            super(MainActivity.this);
            setBackground(Ui.rippleOval(Ui.PRIMARY_CONTAINER));
            setClickable(true);

            icon = new ImageView(MainActivity.this);
            icon.setImageDrawable(Glyph.of(Glyph.REFRESH, Ui.ON_PRIMARY_CONTAINER));
            addView(icon, new FrameLayout.LayoutParams(
                    Ui.dp(MainActivity.this, 24), Ui.dp(MainActivity.this, 24), Gravity.CENTER));

            arc = new SpinnerArc();
            arc.setVisibility(GONE);
            addView(arc, new FrameLayout.LayoutParams(
                    Ui.dp(MainActivity.this, 26), Ui.dp(MainActivity.this, 26), Gravity.CENTER));

            setOnClickListener(v -> {
                if (!busy) {
                    startRun();
                }
            });
        }

        void setBusy(boolean b) {
            if (busy == b) {
                return;
            }
            busy = b;
            icon.setVisibility(b ? GONE : VISIBLE);
            arc.setVisibility(b ? VISIBLE : GONE);
            if (b) {
                arc.start();
            } else {
                arc.stop();
            }
            setEnabled(!b);
            setClickable(!b);
            setAlpha(b ? 0.85f : 1f);
        }
    }

    /** FAB 里的旋转弧（自绘，不引第三方 loading 库）。 */
    private final class SpinnerArc extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF oval = new RectF();
        private final android.animation.ValueAnimator animator;
        private float angle;

        SpinnerArc() {
            super(MainActivity.this);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(Ui.dp(MainActivity.this, 2.5f));
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setColor(Ui.ON_PRIMARY_CONTAINER);
            animator = android.animation.ValueAnimator.ofFloat(0f, 360f);
            animator.setDuration(900L);
            animator.setRepeatCount(android.animation.ValueAnimator.INFINITE);
            animator.setInterpolator(new LinearInterpolator());
            animator.addUpdateListener(a -> {
                angle = (float) a.getAnimatedValue();
                invalidate();
            });
        }

        void start() {
            if (!animator.isStarted()) {
                animator.start();
            }
        }

        void stop() {
            animator.cancel();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float inset = paint.getStrokeWidth() / 2f;
            oval.set(inset, inset, getWidth() - inset, getHeight() - inset);
            canvas.drawArc(oval, angle, 260f, false, paint);
        }
    }
}
