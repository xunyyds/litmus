package io.litmus.canary;

import android.app.Activity;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 应用内 HTML 报告预览：{@link WebView} 加载 {@link HtmlReport} 生成的单文件 HTML。
 *
 * <p>为什么单独一个 Activity 而不是塞进主界面：报告是「目的地」不是「上下文」，
 * 全屏读、返回即回，用 Activity 最自然；顺带 CLI/CI 也能用
 * {@code adb shell am start -n io.litmus.canary/.ReportViewer} 直接拉起（exported=true 是有意的）。
 *
 * <p>支持两个入参（方便验收与后续 CLI 复用）：
 * <ul>
 *   <li>{@code --es html <absolute path>}：渲染指定文件；</li>
 *   <li>{@code --ez generate true}：进入时先调 {@link HtmlReport} 重新生成再渲染。</li>
 * </ul>
 * 都不给时：渲染最近一份；一份都没有就现场生成。
 *
 * <p><b>安全姿势</b>（这是渲染自家生成的文件，但仍按外部内容对待）：
 * 关 JS、关 DOM Storage、关 database、禁 content:// 访问、禁 file 跨源、
 * 所有跳转一律拦掉、再加一层 {@code setBlockNetworkLoads(true)} —— 报告里没有任何外链，
 * 但万一将来有人往文案里塞链接，也不会被点开或联网加载。
 */
public final class ReportViewer extends Activity {

    /** 指定要渲染的 HTML 绝对路径。 */
    static final String EXTRA_HTML = "html";
    /** 进入时先重新生成一份再渲染。 */
    static final String EXTRA_GENERATE = "generate";

    private WebView web;
    private File current;

    // ================================================================ 生命周期

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildRoot());
        try {
            getWindow().setStatusBarColor(Ui.SURFACE);
            getWindow().setNavigationBarColor(Ui.SURFACE);
        } catch (Throwable ignored) {
        }
        resolveAndLoad();
    }

    /** 解析「渲染哪一份」，必要时现生成。 */
    private void resolveAndLoad() {
        Intent intent = getIntent();
        String path = intent == null ? null : intent.getStringExtra(EXTRA_HTML);
        boolean generate = intent != null && intent.getBooleanExtra(EXTRA_GENERATE, false);

        // 允许 path 带 #anchor（例如 ...report-x.html#blind）：CI 直接跳到某一节截图用。
        // 坑：带 # 的字符串不能直接喂给 File.exists()，必须先拆开。
        String anchor = "";
        if (path != null) {
            int hash = path.lastIndexOf('#');
            if (hash > 0) {
                anchor = path.substring(hash);
                path = path.substring(0, hash);
            }
        }

        File target = path == null || path.isEmpty() ? null : new File(path);
        if (generate || target == null || !target.exists()) {
            File fresh = generateToCache();
            if (fresh != null) {
                target = fresh;
            }
        }
        if (target == null || !target.exists()) {
            toast("还没有可看的报告：先跑一次检测");
            finish();
            return;
        }
        current = target;
        // 自检口径：file:// + 绝对路径，不经过任何 http 服务
        web.loadUrl("file://" + target.getAbsolutePath() + anchor);
    }

    /** 现场生成：写进 cache（不污染 files/litmus 里的正式产物）。 */
    private File generateToCache() {
        JSONObject report = LitmusApp.report();
        if (report == null) {
            return null;
        }
        try {
            File dir = new File(getCacheDir(), "html");
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            File f = new File(dir, "report-" + HtmlReport.runId(report) + ".html");
            writeUtf8(f, HtmlReport.render(this, report));
            return f;
        } catch (Throwable t) {
            toast("生成 HTML 失败：" + t);
            return null;
        }
    }

    // ================================================================ 界面

    private View buildRoot() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.SURFACE);
        root.setFitsSystemWindows(true);

        root.addView(buildBar(), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 48)));

        FrameLayout box = new FrameLayout(this);
        web = new WebView(this);
        web.setBackgroundColor(Ui.SURFACE);
        harden(web);
        box.addView(web, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.addView(box, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        // 底部留白：避开手势导航区，否则最后一行会被系统手势条压住
        View spacer = new View(this);
        spacer.setBackgroundColor(Ui.SURFACE);
        root.addView(spacer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 18)));
        return root;
    }

    private View buildBar() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Ui.SURFACE);
        bar.setPadding(Ui.dp(this, 16), 0, Ui.dp(this, 8), 0);

        TextView title = new TextView(this);
        title.setText(getString(R.string.app_name) + " · 报告");
        title.setTextColor(Ui.ON_SURFACE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        bar.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        bar.addView(barAction("关闭", this::finish));
        bar.addView(barAction("导出", this::exportCurrent));
        bar.addView(barAction("分享文本", this::shareText));
        return bar;
    }

    private TextView barAction(String text, Runnable action) {
        TextView b = new TextView(this);
        b.setText(text);
        b.setTextColor(Ui.ON_SURFACE_VARIANT);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        b.setGravity(Gravity.CENTER);
        b.setPadding(Ui.dp(this, 10), Ui.dp(this, 8), Ui.dp(this, 10), Ui.dp(this, 8));
        b.setBackground(Ui.ripple(0x00000000, Ui.dp(this, 999)));
        b.setClickable(true);
        b.setFocusable(true);
        b.setOnClickListener(v -> action.run());
        return b;
    }

    // ================================================================ WebView 加固

    /** 关掉一切能联网/执行脚本的开关；跳转全部拦掉。 */
    static void harden(WebView view) {
        WebSettings s = view.getSettings();
        s.setJavaScriptEnabled(false);
        s.setDomStorageEnabled(false);
        s.setDatabaseEnabled(false);
        s.setSaveFormData(false);
        s.setAllowFileAccess(true);
        s.setAllowContentAccess(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);
        s.setSupportZoom(false);
        s.setDisplayZoomControls(false);
        s.setBuiltInZoomControls(false);
        try {
            // 双保险：报告里没有任何外链，但即使将来有也不会被联网加载
            s.setBlockNetworkLoads(true);
        } catch (Throwable ignored) {
        }
        view.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest request) {
                return true;   // 一律不跳：报告是死文件，没有「点进去」这回事
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView v, String url) {
                return true;
            }
        });
        view.setLongClickable(false);
        view.setHapticFeedbackEnabled(false);
    }

    // ================================================================ 动作

    /** 导出到 getExternalFilesDir(null)/litmus/report-<runId>.html（与主界面同一套路径）。 */
    private void exportCurrent() {
        if (current == null) {
            toast("没有可导出的报告");
            return;
        }
        try {
            File dir = new File(externalBase(), "litmus");
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            File out = new File(dir, current.getName());
            FileOutputStream fos = new FileOutputStream(out);
            try {
                fos.write(HtmlReport.render(this, LitmusApp.report()).getBytes(StandardCharsets.UTF_8));
            } finally {
                fos.close();
            }
            toast("已导出：" + out.getAbsolutePath());
        } catch (Throwable t) {
            toast("导出失败：" + t);
        }
    }

    /** 分享文本：一份能直接贴进聊天框的摘要（HTML 全文太大，不适合当文本发）。 */
    private void shareText() {
        JSONObject report = LitmusApp.report();
        StringBuilder sb = new StringBuilder();
        sb.append(getString(R.string.app_name)).append(" 检测报告");
        if (report != null) {
            JSONObject summary = report.optJSONObject("summary");
            JSONObject run = report.optJSONObject("run");
            if (run != null) {
                sb.append(" · run ").append(run.optString("id", ""));
            }
            if (summary != null) {
                Object score = summary.opt("score");
                sb.append("\n总分：").append(score instanceof Number
                        ? String.format(java.util.Locale.US, "%.1f", ((Number) score).doubleValue())
                        : "无法评分（向量全部 UNKNOWN）");
                sb.append("\n通过 ").append(summary.optInt("clean", 0))
                        .append(" · 可疑 ").append(summary.optInt("suspect", 0))
                        .append(" · 被坐实 ").append(summary.optInt("tampered", 0))
                        .append(" · 测不了 ").append(summary.optInt("unknown", 0));
            }
            JSONArray signals = report.optJSONArray("signals");
            StringBuilder reds = new StringBuilder();
            for (int i = 0; signals != null && i < signals.length(); i++) {
                JSONObject s = signals.optJSONObject(i);
                if (s != null && "TAMPERED".equals(s.optString("verdict", ""))) {
                    if (reds.length() > 0) {
                        reds.append('、');
                    }
                    reds.append(s.optString("id", "?"));
                }
            }
            if (reds.length() > 0) {
                sb.append("\n被坐实：").append(reds);
            }
        }
        if (current != null) {
            sb.append("\nHTML：").append(current.getAbsolutePath());
        }
        try {
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.app_name) + " 检测报告");
            send.putExtra(Intent.EXTRA_TEXT, sb.toString());
            startActivity(Intent.createChooser(send, "分享报告摘要"));
        } catch (Throwable t) {
            try {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(ClipData.newPlainText("litmus-report", sb.toString()));
                    toast("没有分享目标，已复制摘要到剪贴板");
                }
            } catch (Throwable ignored) {
                toast("分享失败：" + t);
            }
        }
    }

    // ================================================================ 降级：内嵌 Dialog 预览

    /**
     * 清单里没有 {@link ReportViewer}（或 Activity 起不来）时的降级预览。
     *
     * <p>调用方必须 toast 一句「用内嵌视图打开」——**不许静默切换**，否则用户会以为按钮坏了。
     */
    static void showInline(Activity host, File html) {
        if (host == null || host.isFinishing() || html == null || !html.exists()) {
            return;
        }
        Context dark = new ContextThemeWrapper(host, android.R.style.Theme_DeviceDefault);
        Dialog dialog = new Dialog(dark);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);

        LinearLayout root = new LinearLayout(dark);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.SURFACE);
        root.setFitsSystemWindows(true);

        LinearLayout bar = new LinearLayout(dark);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Ui.SURFACE);
        bar.setPadding(Ui.dp(host, 16), Ui.dp(host, 10), Ui.dp(host, 10), Ui.dp(host, 10));
        TextView title = new TextView(dark);
        title.setText("报告预览（内嵌）");
        title.setTextColor(Ui.ON_SURFACE);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        bar.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView close = new TextView(dark);
        close.setText("关闭");
        close.setTextColor(Ui.ON_SURFACE_VARIANT);
        close.setPadding(Ui.dp(host, 12), Ui.dp(host, 8), Ui.dp(host, 12), Ui.dp(host, 8));
        close.setClickable(true);
        close.setOnClickListener(v -> dialog.dismiss());
        bar.addView(close, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(bar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        WebView view = new WebView(dark);
        view.setBackgroundColor(Ui.SURFACE);
        harden(view);
        root.addView(view, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        view.loadUrl("file://" + html.getAbsolutePath());

        dialog.setContentView(root);
        Window w = dialog.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            w.addFlags(android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            w.setDimAmount(0.5f);
            w.setLayout(android.view.WindowManager.LayoutParams.MATCH_PARENT,
                    android.view.WindowManager.LayoutParams.MATCH_PARENT);
        }
        dialog.show();
        if (w != null) {
            w.setLayout(android.view.WindowManager.LayoutParams.MATCH_PARENT,
                    android.view.WindowManager.LayoutParams.MATCH_PARENT);
        }
    }

    // ================================================================ 小工具

    private File externalBase() {
        File base = getExternalFilesDir(null);
        return base == null ? getFilesDir() : base;
    }

    static void writeUtf8(File f, String text) throws Exception {
        File parent = f.getParentFile();
        if (parent != null) {
            //noinspection ResultOfMethodCallIgnored
            parent.mkdirs();
        }
        FileOutputStream fos = new FileOutputStream(f);
        try {
            fos.write(text.getBytes(StandardCharsets.UTF_8));
        } finally {
            fos.close();
        }
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }
}
