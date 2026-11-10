package io.litmus.canary;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.litmus.core.BuildInfo;
import io.litmus.core.VectorDocs;

/**
 * 把 {@code report.json} 渲染成**单文件自包含 HTML**（九段式，见 docs/07-交互与报告规范.md §7）。
 *
 * <p>为什么 App 也要能出这份 HTML：JSON 给机器看、原生界面给自己快速扫一眼，
 * 而「发给别人看 / 存档 / 贴进 issue」要的是一份别人不用装 App 也能读的报告。
 *
 * <p>硬约束（会被 grep 审）：
 * <ul>
 *   <li>CSS 全部内联在 {@code <style>} 里，**没有 script / 没有外链 / 没有 CDN / 没有 @import**；</li>
 *   <li>正文里任何 {@code http://}、{@code https://} 都会被 {@link #esc} 洗成 {@code hxxp(s)}；</li>
 *   <li>零第三方依赖：只用 {@code org.json} + {@code StringBuilder}；</li>
 *   <li>文案全部来自 {@link VectorDocs}（zh/plain/bypass），UI 不硬编码长句 —— 保证 App 与 CLI 说法一致；</li>
 *   <li>{@code score == null} 时 ① 必须写「无法评分」，**任何地方都不许出现 100 分假象**。</li>
 * </ul>
 *
 * <p>移动端简化（相对 CLI 的 {@code examples/report-C2-repack.html}）：
 * <ul>
 *   <li>没有目录锚点（手机上跳来跳去不如顺读）；</li>
 *   <li>所有表格降为**两列**（字段名 | 值），宽内容放进 {@code .scrollx} 横向滚；</li>
 *   <li>⑨ 附录的 47 行宽表改为「每条向量一个小块」，避免手机上 8 列挤压；</li>
 *   <li>App 侧没有基线/构建产物哈希，③ 与 ⑦ 只能给实测值与口径说明，不编期望值。</li>
 * </ul>
 */
final class HtmlReport {

    private HtmlReport() {
    }

    /** 产品名唯一来源：{@code @string/app_name}。改名时只动 strings.xml，本文件不用改。 */
    static String productName(Context ctx) {
        try {
            return ctx.getString(R.string.app_name);
        } catch (Throwable t) {
            return "";
        }
    }

    /** 取 runId（生成文件名、标题、复现命令都要用）。 */
    static String runId(JSONObject report) {
        JSONObject run = report == null ? null : report.optJSONObject("run");
        String id = run == null ? "" : run.optString("id", "");
        return id.isEmpty() ? "unknown" : id;
    }

    // ================================================================ 入口

    static String render(Context ctx, JSONObject report) {
        JSONObject producer = report == null ? null : report.optJSONObject("producer");
        JSONObject run = report == null ? null : report.optJSONObject("run");
        JSONObject app = report == null ? null : report.optJSONObject("app");
        JSONObject device = report == null ? null : report.optJSONObject("device");
        JSONObject facts = report == null ? null : report.optJSONObject("facts");
        JSONObject summary = report == null ? null : report.optJSONObject("summary");
        JSONArray signalArr = report == null ? null : report.optJSONArray("signals");
        JSONArray catArr = summary == null ? null : summary.optJSONArray("categories");

        List<JSONObject> signals = new ArrayList<>();
        for (int i = 0; signalArr != null && i < signalArr.length(); i++) {
            JSONObject s = signalArr.optJSONObject(i);
            if (s != null) {
                signals.add(s);
            }
        }

        double score = scoreOf(summary);
        boolean scored = summary != null && summary.opt("score") instanceof Number;
        int clean = summary == null ? 0 : summary.optInt("clean", 0);
        int suspect = summary == null ? 0 : summary.optInt("suspect", 0);
        int tampered = summary == null ? 0 : summary.optInt("tampered", 0);
        int unknown = summary == null ? 0 : summary.optInt("unknown", 0);
        int error = summary == null ? 0 : summary.optInt("error", 0);
        int flaky = summary == null ? 0 : summary.optInt("flaky", 0);
        int unjudged = unknown + error + flaky;

        List<String[]> blind = blindSpots(catArr, signals, tampered > 0);
        double denom = denomWeight(catArr);

        String runId = run == null ? "unknown" : run.optString("id", "unknown");
        String version = producer == null ? BuildInfo.version : producer.optString("version", BuildInfo.version);
        String flavor = producer == null ? BuildInfo.flavor : producer.optString("flavor", BuildInfo.flavor);
        boolean hasNative = producer != null ? producer.optBoolean("hasNative", false) : BuildInfo.hasNative;

        StringBuilder h = new StringBuilder(48 * 1024);
        h.append("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
                .append("<title>").append(esc(productName(ctx))).append(" 检测报告</title>\n")
                .append("<style>").append(css()).append("</style>\n</head>\n<body>\n<div class=\"wrap\">\n");

        // ---------------- 页头：品牌 + 分数 + 元信息 ----------------
        h.append("<div class=\"topbar\"><div class=\"brand\"><span class=\"dot\"></span>")
                .append("<span>").append(esc(productName(ctx))).append("</span>")
                .append("<span class=\"eyebrow\">Tamper Detection Report</span></div>")
                // 标题只写「检测报告」：runId 是给机器看的，放 ⑨ 附录最后一行就够了
                .append("<h1>检测报告</h1>")
                .append("<p class=\"meta\">")
                .append(esc(pkgName(app) + " · " + version + " " + flavor + " · " + deviceLine(device)))
                .append("</p>\n<p class=\"meta\">")
                .append(esc(collectedText(run) + " · profile standard · 报告来源 内置检测"))
                .append("</p></div>\n");

        h.append("<div class=\"hero\"><div class=\"scorebox\">")
                .append("<div class=\"score-num\" style=\"color:").append(scoreColor(score, scored)).append("\">")
                .append(scored ? String.format(Locale.US, "%.1f", score) : "—").append("</div>")
                .append("<div class=\"score-den\">/ 100</div></div>")
                .append("<div class=\"score-cap\">")
                .append(scored
                        ? "分值越高 = 我们越看不出来；满分不等于「没问题」，可能是「没抓到」。"
                        : "无法评分：所有向量都停在「测不了」，这<strong>不等于</strong>「干净」。")
                .append("</div><div class=\"chips\">")
                .append("<span class=\"chip primary\">profile standard</span>")
                .append("<span class=\"chip ").append(tampered > 0 ? "tampered" : "").append("\">")
                .append(tampered > 0 ? "包已改动" : "未见坐实").append("</span>")
                .append("<span class=\"chip\">").append(signals.size()).append(" 条向量</span>")
                .append("<span class=\"chip\">").append(esc(version + " · " + flavor)).append("</span>")
                .append("<span class=\"chip\">native ").append(hasNative ? "已加载" : "未加载")
                .append("</span></div></div>\n");

        // ---------------- ① 一句话结论 ----------------
        h.append("<section id=\"conclusion\">\n<h2>① 一句话结论</h2>\n");
        if (!scored) {
            h.append("<p>这份报告<strong>无法评分</strong>：").append(signals.size())
                    .append(" 条向量全部或大部分停在「测不了（UNKNOWN）」——")
                    .append("这既不能当作「干净」，也不能当作「被改」，只能说明这台设备上我们看不出来。</p>\n");
            h.append("<p>先把 native 与探针链路修通（见 ④ 每类里「测不了」的条目），再谈分数。</p>\n");
        } else if (tampered > 0) {
            h.append("<p>这个包<strong>被改过</strong>（").append(reasonPhrase(signals)).append("）")
                    .append(tamperedInPackage(signals)
                            ? "，其中「" + esc(worstLabel(catArr)) + "」掉得最狠（"
                            + esc(worstScore(catArr)) + " 分，" + tampered + " 条被坐实）。"
                            : "，但没有一条落在包完整性上 —— 改动发生在<strong>运行时</strong>，不在 APK 里。")
                    .append("</p>\n");
            if (blind.isEmpty()) {
                h.append("<p>六类都至少动了一下，没有整类失明。</p>\n");
            } else {
                h.append("<p>但「").append(esc(joinLabels(blind))).append("」一条都没抓到 —— ")
                        .append("这几类对本次修补是失明的，见 ⑥。</p>\n");
            }
        } else if (suspect > 0) {
            h.append("<p>这个包<strong>没有一条被坐实</strong>，但有 ").append(suspect)
                    .append(" 条停在「可疑」：有痕迹、证据不足以下定论，多半是设备噪声，见 ⑦。</p>\n");
        } else {
            h.append("<p>六类里<strong>没有一条被坐实</strong>，也没有可疑项。</p>\n");
        }
        h.append("<p>").append(scoreSentence(score, scored)).append("</p>\n");
        h.append("<p class=\"note\">术语：").append(badge("CLEAN")).append("、").append(badge("SUSPECT"))
                .append("、").append(badge("TAMPERED")).append("、").append(badge("UNKNOWN"))
                .append("、").append(badge("ERROR")).append("、").append(badge("FLAKY"))
                .append("。后三种不计分，也<strong>不算干净</strong>。tier 是证据强度：")
                .append("A 级 = 不变量/密码学，B 级 = 交叉视图，C 级 = 特征匹配（只能出可疑）。</p>\n");
        h.append("</section>\n");

        // ---------------- ② 三个数字 ----------------
        h.append("<section id=\"numbers\">\n<h2>② 三个数字</h2>\n<div class=\"kpis\">\n");
        h.append(kpi(scored ? String.format(Locale.US, "%.1f", score) : "—",
                scoreColor(score, scored), "总分",
                scored ? "越高说明我们越看不出来（100 = 一条篡改都没抓到）"
                        : "全部测不了时不给分，避免「100 分 = 干净」的误读"));
        h.append(kpi(blind.size() + " 类", blind.isEmpty() ? "#B6F09C" : "#F9E2AF", "盲区类别",
                blind.isEmpty() ? "没有整类失明" : "包被改过却整类满分的类别，见 ⑥"));
        h.append(kpi("—", "#938F99", "误报向量",
                "App 侧没有基线，误报要靠 CLI 的 --baseline 判（不编数）"));
        h.append("</div>\n</section>\n");

        // ---------------- ③ 这次改了什么 ----------------
        h.append("<section id=\"changed\">\n<h2>③ 这次改了什么</h2>\n");
        h.append("<p>").append(changedStory(signals, tampered, suspect)).append("</p>\n");
        h.append("<div class=\"card\">").append(table2(new String[][]{
                {"签名证书（sha256）", certCompare(facts)},
                {"APK 全文件哈希（sha256）", "构建产物期望值：<em>由 CLI 比对</em><br>本次实测：<code>"
                        + esc(shortHash(fact(facts, "apk.sha256"))) + "</code>"},
                {"打包指纹（ZipEntry）", "构建产物期望值：<em>由 CLI 比对</em><br>本次实测：<code>"
                        + esc(shortHash(fact(facts, "apk.zip.fingerprint"))) + "</code>"},
                {"安装来源", "installer = <code>" + esc(orDash(fact(facts, "apk.installer")))
                        + "</code>（adb 侧载时为空，属正常基线）"},
        })).append("</div>\n");
        h.append("<p class=\"note\">哈希/指纹/签名这三项里只要有一项对不上，就说明装上去的这份包不是构建的那一份。")
                .append("为什么 App 只能给实测值：APK 的哈希是签完名才有的，构建期烘不进它自己（契约 §4.1），")
                .append("所以期望值只在 CLI 手里。签名证书不一样 —— 它在构建前就已知，烘在 assets 里，所以本页能直接比。</p>\n");
        h.append("</section>\n");

        // ---------------- ④ 逐类判断 ----------------
        h.append("<section id=\"categories\">\n<h2>④ 逐类判断</h2>\n");
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(catArr, def[0]);
            List<JSONObject> sigs = inCategory(signals, def[0]);
            if (sigs.isEmpty() && c == null) {
                continue;
            }
            Double catScore = c == null ? null : numberOrNull(c.opt("score"));
            h.append("<h3 class=\"sub\">").append(esc(def[1])).append("（").append(esc(def[0])).append("）· ")
                    .append(catScore == null ? "—" : String.format(Locale.US, "%.1f", catScore))
                    .append(" 分</h3>\n");
            h.append("<p>").append(categoryStory(def[0], def[1], sigs, catScore, tampered > 0)).append("</p>\n");

            List<JSONObject> notClean = new ArrayList<>();
            for (JSONObject s : sigs) {
                String v = s.optString("verdict", "UNKNOWN");
                if (!"CLEAN".equals(v)) {
                    notClean.add(s);
                }
            }
            if (notClean.isEmpty()) {
                h.append("<p class=\"ok\">这一类 ").append(sigs.size()).append(" 条全部通过（CLEAN）。</p>\n");
            } else {
                // 手机上两列表格会把 id 挤成一字一行（inj.pr / oc.env），所以这里改成堆叠块：
                // 一行 id + 徽章 + tier，下一行证据。可读性优先于「表格」这个形式。
                h.append("<div class=\"card\">\n");
                for (JSONObject s : notClean) {
                    h.append("<div class=\"vec\"><code>").append(esc(s.optString("id", "?"))).append("</code> ")
                            .append(badge(s.optString("verdict", "UNKNOWN")))
                            .append(" <span class=\"tierc\">tier ").append(esc(s.optString("tier", "-")))
                            .append(" · 权重 ").append(s.optInt("weight", 0)).append("</span>")
                            .append("<div class=\"ev\">")
                            .append(md(shortText(s.optString("evidence", ""), 160)))
                            .append("</div></div>\n");
                }
                h.append("</div>\n");
            }
        }
        h.append("</section>\n");

        // ---------------- ⑤ 被坐实的问题 ----------------
        h.append("<section id=\"confirmed\">\n<h2>⑤ 被坐实的问题</h2>\n");
        List<JSONObject> reds = new ArrayList<>();
        for (JSONObject s : signals) {
            if ("TAMPERED".equals(s.optString("verdict", ""))) {
                reds.add(s);
            }
        }
        if (reds.isEmpty()) {
            h.append("<p>本次没有一条被坐实。").append(tampered > 0 ? "" : "这不等于「干净」")
                    .append("：也可能是这一类整体失明（见 ⑥）或根本没测（见 ④ 的「测不了」）。</p>\n");
        } else {
            h.append("<p>").append(reds.size())
                    .append(" 条向量拿到了 A/B 级证据，直接判定为被改。每条都按「判据 / 证据 / 意味着什么 / 怎么修」写清楚。</p>\n");
            for (JSONObject s : sortByWeight(reds)) {
                String id = s.optString("id", "?");
                String cat = s.optString("category", "");
                h.append("<div class=\"flag bad\">\n<h4>").append(esc(id)).append(" · ")
                        .append(esc(Ui.categoryZh(cat))).append(" · ").append(esc(s.optString("tier", "B")))
                        .append(" 级</h4>\n");
                h.append(table2(new String[][]{
                        {"判据", md(VectorDocs.zh(id))},
                        {"证据", "<code>" + esc(shortText(s.optString("evidence", ""), 200)) + "</code>"},
                        {"意味着什么", md(VectorDocs.plain(id)) + " " + tierSentence(s.optString("tier", "B"))},
                        {"怎么修 / 怎么绕过", md(VectorDocs.bypass(id))},
                })).append("\n</div>\n");
            }
        }
        h.append("</section>\n");

        // ---------------- ⑥ 我们看不见的地方 ----------------
        h.append("<section id=\"blind\">\n<h2>⑥ 我们看不见的地方</h2>\n");
        h.append("<p>盲区（blind spot）= 包<strong>确实被改过</strong>，但整类检测一条都没抓到。")
                .append("这是我们要补的洞，不是用户的错。每一类都给「为什么可能是洞」和「怎么验证是不是洞」。</p>\n");
        if (blind.isEmpty()) {
            h.append("<p>本次没有可判定的盲区：")
                    .append(tampered > 0 ? "六类都至少抓到一条非干净信号。" : "没有一条被坐实，因此分不清「真的干净」和「整类失明」——要先有坐实项，才谈得上盲区。")
                    .append("</p>\n");
        } else {
            for (String[] b : blind) {
                String catId = b[0];
                String catZh = b[1];
                String catScore = b[2];
                int n = Integer.parseInt(b[3]);
                List<JSONObject> sigs = inCategory(signals, catId);
                h.append("<div class=\"flag blind\">\n<h4>⚠ ").append(esc(catZh)).append("（").append(esc(catId))
                        .append("）· ").append(esc(catScore)).append(" 分 · ").append(n).append(" 条向量全干净</h4>\n");
                h.append("<p>").append(esc(catZh)).append(" ").append(n)
                        .append(" 条向量全部是「干净」，可这个包<strong>确实被改过</strong>：")
                        .append("也就是说整类检测对这次修补一条都没抓到。</p>\n");
                h.append("<p><strong>为什么可能是洞：</strong>").append(tierComposition(sigs)).append("</p>\n");
                h.append("<p><strong>怎么验证是不是洞：</strong>1）换一台真机（非模拟器、非多开）跑同一个包：")
                        .append("该类仍满分 → 说明它测的是「环境像不像模拟器」，与「包被改」本来就无关；")
                        .append("2）造一份「真的动了这一面」的样板包，如果它还是满分 → 真洞；")
                        .append("3）给这一类补一条 tier A 的不变量再跑，若新向量也是干净，基本可以确诊。</p>\n");
                h.append("</div>\n");
            }
        }
        h.append("</section>\n");

        // ---------------- ⑦ 环境噪声 ----------------
        h.append("<section id=\"noise\">\n<h2>⑦ 环境噪声</h2>\n");
        h.append("<p>这次<strong>不带基线</strong>跑（App 侧没有 <code>--baseline</code> 这个概念），")
                .append("所以无法区分「设备本来就脏」和「这次修补引入的问题」：下面的分数是<strong>绝对值</strong>，")
                .append("不是相对某台干净设备的增量。</p>\n");
        h.append("<p>另外要留意：").append(suspect).append(" 条停在可疑（有痕迹但证据不足）；")
                .append(unjudged).append(" 条完全测不了（这类不计分，但也不是「干净」）；")
                .append(blind.size()).append(" 类整体失明（见 ⑥）。").append("</p>\n");
        h.append("<p>建议：用 CLI 在同一台设备上带 <code>--baseline</code> 再跑一次干净包，把这次的红叉逐条对照；")
                .append("同一份包重复跑如果分数抖动，抖动幅度本身就是噪声底（<em>待实测</em>）。</p>\n");
        h.append("</section>\n");

        // ---------------- ⑧ 怎么让分数上去 ----------------
        h.append("<section id=\"actions\">\n<h2>⑧ 怎么让分数上去</h2>\n");
        h.append("<p class=\"note\">收益怎么算：把某一类补到 100 分（或修掉一条红叉）后，按类别权重折算成总分变化。")
                .append("<strong>所有数字都是估算</strong>，不含「改完之后检测能力是否真的变强」这层不确定性。</p>\n");
        List<String[]> actions = actions(catArr, signals, blind, denom, scored);
        if (actions.isEmpty()) {
            h.append("<p>没有可提分的项：要么六类都已满分，要么剩下的都是「测不了」（测不了不进分母，修它不加分，但能让报告更诚实）。</p>\n");
        } else {
            for (String[] a : actions) {
                h.append("<div class=\"card\">\n<div class=\"act\">").append(esc(a[0])).append("</div>\n");
                h.append(table2(new String[][]{
                        {"为什么", md(a[1])},
                        {"预计收益", "<strong>" + esc(a[2]) + "</strong>"},
                        {"成本", esc(a[3])},
                        {"怎么做", md(a[4])},
                })).append("\n</div>\n");
            }
        }
        h.append("</section>\n");

        // ---------------- ⑨ 附录 ----------------
        h.append("<section id=\"appendix\">\n<h2>⑨ 附录</h2>\n");
        h.append("<h3 class=\"sub\">本次运行</h3>\n<div class=\"card\">").append(table2(new String[][]{
                {"schema", "<code>" + esc(report == null ? "" : report.optString("schema", "")) + "</code>"},
                {"生产者", "<code>" + esc(orDash(producer == null ? "" : producer.optString("name", ""))) + "</code>"},
                {"版本", "<code>" + esc(version + " · " + flavor) + "</code>"},
                {"采集时间", "<code>" + esc(orDash(run == null ? "" : run.optString("collectedAt", ""))) + "</code>"},
                {"耗时", esc(orDash(run == null ? "" : String.valueOf(run.optInt("durationMs", 0)) + " ms"))},
                {"向量数", esc(String.valueOf(signals.size()))},
                {"包名 / 进程", "<code>" + esc(orDash(app == null ? "" : app.optString("package", ""))) + "</code>"},
                {"设备", esc(deviceLine(device))},
                {"ABI", "<code>" + esc(orDash(fact(facts, "native.abi"))) + "</code>"},
                {"APK sha256", "<code>" + esc(shortHash(fact(facts, "apk.sha256"))) + "</code>"},
                {"zip 指纹", "<code>" + esc(shortHash(fact(facts, "apk.zip.fingerprint"))) + "</code>"},
                {"证书 sha256", "<code>" + esc(shortHash(actualCert(facts))) + "</code>"},
        })).append("</div>\n");

        h.append("<h3 class=\"sub\">完整向量表（").append(signals.size()).append(" 条，含干净项）</h3>\n");
        for (String[] def : Ui.CATEGORIES) {
            List<JSONObject> sigs = inCategory(signals, def[0]);
            if (sigs.isEmpty()) {
                continue;
            }
            h.append("<div class=\"card\">\n<div class=\"grp\">").append(esc(def[1]))
                    .append(" · ").append(sigs.size()).append(" 条</div>\n");
            for (JSONObject s : sigs) {
                h.append("<div class=\"vec\"><code>").append(esc(s.optString("id", "?"))).append("</code> ")
                        .append(badge(s.optString("verdict", "UNKNOWN")))
                        .append(" <span class=\"tierc\">tier ").append(esc(s.optString("tier", "-")))
                        .append(" · 权重 ").append(s.optInt("weight", 0))
                        .append(" · 置信度 ").append(String.format(Locale.US, "%.2f", s.optDouble("confidence", 0)))
                        .append("</span><div class=\"ev\">").append(md(shortText(s.optString("evidence", ""), 200)))
                        .append("</div></div>\n");
            }
            h.append("\n</div>\n");
        }

        h.append("<h3 class=\"sub\">复现这条结果</h3>\n<pre>").append(esc(
                "adb shell am start -n io.litmus.canary/.MainActivity\n"
                        + "adb logcat -s LitmusReport        # 报告正文（超长会分 LITMUS_REPORT_CHUNK）\n"
                        + "adb pull /sdcard/Android/data/io.litmus.canary/files/litmus/report-" + runId + ".json"))
                .append("</pre>\n");
        // run id 放在 ⑨ 附录的最后一行：它是给机器看的，不该占标题位置
        h.append("<p class=\"note\">run id <span class=\"runchip\">").append(esc(runId)).append("</span></p>\n");
        h.append("</section>\n");

        h.append("<div class=\"foot\">由 ").append(esc(productName(ctx))).append("本地生成（零外链、零脚本）；")
                .append("文案与 CLI 报告同源：schema/vectors.json。</div>\n");
        h.append("</div>\n</body>\n</html>\n");
        return h.toString();
    }

    // ================================================================ 段落文案（按类别/verdict/tier 组装）

    private static String scoreSentence(double score, boolean scored) {
        if (!scored) {
            return "这份报告<strong>无法评分</strong>：可计分的向量一条都没有，所以不给分——"
                    + "「不给分」比「给 0 分」或「给 100 分」都诚实。";
        }
        return "总分 " + String.format(Locale.US, "%.1f", score) + "/100。"
                + "这个分是「我们看着它有多干净」，越高说明越看不出来（100 = 一条篡改都没抓到，0 = 全被抓住）。";
    }

    /** ③ 的叙述：从「哪些 pkg.* 非干净」反推用户做了什么。 */
    private static String changedStory(List<JSONObject> signals, int tampered, int suspect) {
        List<String> nouns = new ArrayList<>();
        for (JSONObject s : signals) {
            if (!"TAMPERED".equals(s.optString("verdict", ""))) {
                continue;
            }
            String id = s.optString("id", "");
            if (id.startsWith("pkg.signature") || id.startsWith("pkg.signing")) {
                add(nouns, "签名");
            } else if (id.equals("pkg.cert.history")) {
                add(nouns, "证书链");
            } else if (id.equals("pkg.codepath.hash")) {
                add(nouns, "内容哈希");
            } else if (id.equals("pkg.zip.fingerprint")) {
                add(nouns, "打包指纹");
            } else if (id.startsWith("pkg.dex")) {
                add(nouns, "dex");
            } else if (id.startsWith("pkg.")) {
                add(nouns, "包内容");
            }
        }
        if (nouns.isEmpty()) {
            if (tampered > 0) {
                return "包本身（签名/哈希/指纹）没有对不上的地方，但运行时被抓到改动 —— 说明修补发生在<strong>内存里</strong>，不在 APK 里。";
            }
            if (suspect > 0) {
                return "签名、哈希、指纹都没有对不上的地方；" + suspect + " 条可疑全部落在设备/运行时面，多半是环境噪声。";
            }
            return "签名、哈希、指纹三项都没有对不上的地方：装上去的就是构建出来的那一份。";
        }
        return String.join("、", nouns) + " 都对不上 —— 整包被<strong>重新签名或重打包</strong>，这是最常见的「换个证书再装一遍」。";
    }

    /** ④ 每类一段人话：只由计数与 tier 组成，不逐条写死。 */
    private static String categoryStory(String catId, String catZh, List<JSONObject> sigs,
                                        Double catScore, boolean modified) {
        int clean = 0;
        int suspect = 0;
        int tampered = 0;
        int unjudged = 0;
        for (JSONObject s : sigs) {
            String v = s.optString("verdict", "UNKNOWN");
            if ("CLEAN".equals(v)) {
                clean++;
            } else if ("SUSPECT".equals(v)) {
                suspect++;
            } else if ("TAMPERED".equals(v)) {
                tampered++;
            } else {
                unjudged++;
            }
        }
        int counted = clean + suspect + tampered;
        StringBuilder sb = new StringBuilder();
        if (counted == 0) {
            sb.append("这一类 ").append(sigs.size()).append(" 条<strong>全部测不了</strong>")
                    .append("（不计分）：说明观测面在这台设备上取不到数据，不代表干净。");
            return sb.toString();
        }
        sb.append("可判定 ").append(counted).append(" 条里 ");
        List<String> parts = new ArrayList<>();
        if (clean > 0) {
            parts.add(clean + " 条干净");
        }
        if (suspect > 0) {
            parts.add(suspect + " 条可疑");
        }
        if (tampered > 0) {
            parts.add(tampered + " 条被坐实");
        }
        sb.append(String.join("，", parts));
        if (unjudged > 0) {
            sb.append("，另有 ").append(unjudged).append(" 条测不了（不计分）");
        }
        sb.append("。");

        JSONObject lead = pickLead(sigs);
        if (lead != null) {
            sb.append("最需要看的是 <strong>").append(esc(lead.optString("id", "?"))).append("</strong>：")
                    .append(badge(lead.optString("verdict", "UNKNOWN")))
                    .append("，置信度 ").append(String.format(Locale.US, "%.2f", lead.optDouble("confidence", 0)))
                    .append("。证据是 <code>").append(esc(shortText(lead.optString("evidence", ""), 120)))
                    .append("</code>。");
        }
        if (catScore != null && catScore >= 99.95 && modified && tampered == 0) {
            sb.append("<strong>注意</strong>：包确实被改过，这一类却拿了满分 —— 也就是说它对着这次修补完全瞎了，见 ⑥。");
        }
        return sb.toString();
    }

    /** 挑「最该看」的那条：先按 verdict 严重度，再按权重。 */
    private static JSONObject pickLead(List<JSONObject> sigs) {
        JSONObject best = null;
        int bestRank = -1;
        for (JSONObject s : sigs) {
            String v = s.optString("verdict", "UNKNOWN");
            int rank;
            if ("TAMPERED".equals(v)) {
                rank = 30;
            } else if ("SUSPECT".equals(v)) {
                rank = 20;
            } else if ("UNKNOWN".equals(v) || "ERROR".equals(v) || "FLAKY".equals(v)) {
                rank = 10;
            } else {
                continue;
            }
            rank += Math.min(9, s.optInt("weight", 0));
            if (rank > bestRank) {
                bestRank = rank;
                best = s;
            }
        }
        return best;
    }

    private static String tierSentence(String tier) {
        if ("A".equals(tier)) {
            return "A 级结论本身就是不变量（密码学/字节比对），出现就意味着改动一定发生过。";
        }
        if ("C".equals(tier)) {
            return "C 级是特征匹配，单独出现只说明「像」，需要 A/B 级佐证才该下重判。";
        }
        return "B 级是交叉视图，通常要两条以上同类证据才下结论。";
    }

    /** ⑥ 的「为什么可能是洞」：只由 tier 构成说话。 */
    private static String tierComposition(List<JSONObject> sigs) {
        int a = 0;
        int b = 0;
        int c = 0;
        for (JSONObject s : sigs) {
            String t = s.optString("tier", "B");
            if ("A".equals(t)) {
                a++;
            } else if ("C".equals(t)) {
                c++;
            } else {
                b++;
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("这一类的构成是 ").append(sigs.size()).append(" 条：A 级 ").append(a)
                .append(" 条、B 级 ").append(b).append(" 条、C 级 ").append(c).append(" 条。");
        if (a + b == 0) {
            sb.append("一条 A/B 级的不变量都没有 —— C 级只认<strong>见过的痕迹</strong>，")
                    .append("这次修补恰好没留下它们，但下一次的修补只要多花一步就能绕开；")
                    .append("整类没有不变量，等于这一类只能靠对手犯错。");
        } else {
            sb.append("里面确实有更强的证据级别，但它们对这次修补没反应 —— ")
                    .append("要么探针没覆盖到真正的改动点，要么这些不变量的观测面选错了。");
        }
        return sb.toString();
    }

    /** ⑧ 行动清单：先修红叉，再消可疑，最后给盲区补不变量；每条都带估算收益（R6）。 */
    private static List<String[]> actions(JSONArray cats, List<JSONObject> signals,
                                          List<String[]> blind, double denom, boolean scored) {
        List<String[]> out = new ArrayList<>();
        if (!scored || denom <= 0) {
            return out;
        }
        // 1) 红叉：每条最多取该类别权重最高的 2 条
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(cats, def[0]);
            if (c == null || numberOrNull(c.opt("score")) == null) {
                continue;
            }
            double a = c.optDouble("weight", 0);
            double countedW = countedWeight(inCategory(signals, def[0]));
            List<JSONObject> reds = new ArrayList<>();
            for (JSONObject s : inCategory(signals, def[0])) {
                if ("TAMPERED".equals(s.optString("verdict", ""))) {
                    reds.add(s);
                }
            }
            int taken = 0;
            for (JSONObject s : sortByWeight(reds)) {
                if (taken++ >= 2 || countedW <= 0) {
                    break;
                }
                double gain = a * (100.0 * s.optInt("weight", 3) / countedW) / denom;
                if (gain <= 0.05) {
                    continue;
                }
                out.add(new String[]{
                        "处理 " + s.optString("id", "?") + "（" + def[1] + "）",
                        "它是可判定项里权重 " + s.optInt("weight", 3) + " 的红叉，「" + def[1] + "」的分数主要被它拉着。",
                        "预计 +" + String.format(Locale.US, "%.1f", gain) + " 分（估算）",
                        s.optInt("weight", 3) >= 5 ? "小" : "中",
                        VectorDocs.bypass(s.optString("id", "")),
                });
            }
        }
        // 2) 可疑：整类没有红叉、但分数被压在 100 以下的类别
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(cats, def[0]);
            if (c == null) {
                continue;
            }
            Double cs = numberOrNull(c.opt("score"));
            if (cs == null || cs >= 99.95 || c.optInt("tampered", 0) > 0) {
                continue;
            }
            double gain = c.optDouble("weight", 0) * (100.0 - cs) / denom;
            if (gain <= 0.05) {
                continue;
            }
            out.add(new String[]{
                    "把 " + def[1] + " 的可疑项判成干净（或改成「测不了」）",
                    "该类 " + c.optInt("suspect", 0) + " 条可疑把分数压在 "
                            + String.format(Locale.US, "%.1f", cs) + " 分；可疑项要么补证据升级成结论，要么承认测不了。",
                    "预计 +" + String.format(Locale.US, "%.1f", gain) + " 分（估算）",
                    "中",
                    "逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。",
            });
        }
        // 3) 盲区：优先级最低（现在已满分，收益要等下次修补）
        for (String[] b : blind) {
            out.add(new String[]{
                    "给 " + b[1] + " 补一条 A 级不变量",
                    "包被改过，这一类向量全干净 —— 现在它不加分，但下次真被改到这一面时，只有它能救。",
                    "预计 +0 分（估算），真正的收益要等下次修补才知道（待实测）",
                    "大",
                    "先按 ⑥ 的「怎么验证是不是洞」确认是真洞，再给这一类加一条 tier A 判据（字节比对/密码学校验，而不是特征匹配）。",
            });
        }
        out.sort((x, y) -> {
            double gx = gainOf(x[2]);
            double gy = gainOf(y[2]);
            if (Math.abs(gx - gy) > 0.001) {
                return Double.compare(gy, gx);
            }
            return Integer.compare(costRank(x[3]), costRank(y[3]));
        });
        return out.size() > 6 ? new ArrayList<>(out.subList(0, 6)) : out;
    }

    private static double gainOf(String label) {
        int i = label.indexOf('+');
        int j = label.indexOf(" 分");
        if (i < 0 || j < 0 || j <= i) {
            return 0;
        }
        try {
            return Double.parseDouble(label.substring(i + 1, j));
        } catch (Throwable t) {
            return 0;
        }
    }

    private static int costRank(String cost) {
        if ("小".equals(cost)) {
            return 0;
        }
        if ("中".equals(cost)) {
            return 1;
        }
        return 2;
    }

    // ================================================================ 计算辅助

    private static double scoreOf(JSONObject summary) {
        if (summary == null) {
            return -1;
        }
        Object raw = summary.opt("score");
        return raw instanceof Number ? ((Number) raw).doubleValue() : -1;
    }

    private static List<String[]> blindSpots(JSONArray cats, List<JSONObject> signals, boolean modified) {
        List<String[]> out = new ArrayList<>();
        if (!modified) {
            return out;
        }
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(cats, def[0]);
            if (c == null) {
                continue;
            }
            Double score = numberOrNull(c.opt("score"));
            int total = c.optInt("total", 0);
            if (score == null || total <= 0) {
                continue;
            }
            if (score >= 99.95 && c.optInt("tampered", 0) == 0 && c.optInt("suspect", 0) == 0) {
                out.add(new String[]{def[0], def[1], String.format(Locale.US, "%.1f", score),
                        String.valueOf(inCategory(signals, def[0]).size())});
            }
        }
        return out;
    }

    private static double denomWeight(JSONArray cats) {
        double sum = 0;
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(cats, def[0]);
            if (c != null && numberOrNull(c.opt("score")) != null) {
                sum += c.optDouble("weight", 0);
            }
        }
        return sum;
    }

    private static double countedWeight(List<JSONObject> sigs) {
        double w = 0;
        for (JSONObject s : sigs) {
            String v = s.optString("verdict", "UNKNOWN");
            if (!"UNKNOWN".equals(v) && !"ERROR".equals(v) && !"FLAKY".equals(v)) {
                w += Math.max(1, Math.min(5, s.optInt("weight", 3)));
            }
        }
        return w;
    }

    private static JSONObject findCat(JSONArray cats, String id) {
        for (int i = 0; cats != null && i < cats.length(); i++) {
            JSONObject c = cats.optJSONObject(i);
            if (c != null && id.equals(c.optString("id", ""))) {
                return c;
            }
        }
        return null;
    }

    private static List<JSONObject> inCategory(List<JSONObject> signals, String cat) {
        List<JSONObject> out = new ArrayList<>();
        for (JSONObject s : signals) {
            if (cat.equals(s.optString("category", ""))) {
                out.add(s);
            }
        }
        return out;
    }

    private static List<JSONObject> sortByWeight(List<JSONObject> in) {
        List<JSONObject> out = new ArrayList<>(in);
        out.sort((x, y) -> Integer.compare(y.optInt("weight", 0), x.optInt("weight", 0)));
        return out;
    }

    private static boolean tamperedInPackage(List<JSONObject> signals) {
        for (JSONObject s : signals) {
            if ("TAMPERED".equals(s.optString("verdict", ""))
                    && s.optString("id", "").startsWith("pkg.")) {
                return true;
            }
        }
        return false;
    }

    private static String reasonPhrase(List<JSONObject> signals) {
        List<String> nouns = new ArrayList<>();
        for (JSONObject s : signals) {
            if (!"TAMPERED".equals(s.optString("verdict", ""))) {
                continue;
            }
            String id = s.optString("id", "");
            if (id.startsWith("pkg.codepath.hash")) {
                add(nouns, "内容哈希");
            } else if (id.startsWith("pkg.zip.fingerprint")) {
                add(nouns, "打包指纹");
            } else if (id.startsWith("pkg.signature") || id.startsWith("pkg.signing")) {
                add(nouns, "签名");
            } else if (id.startsWith("pkg.cert.history")) {
                add(nouns, "证书链");
            }
        }
        if (nouns.isEmpty()) {
            return "运行时被改，包文件本身没问题";
        }
        return String.join("、", nouns) + "都与构建产物对不上";
    }

    private static String worstLabel(JSONArray cats) {
        String best = "—";
        double worst = 101;
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(cats, def[0]);
            if (c == null) {
                continue;
            }
            Double s = numberOrNull(c.opt("score"));
            if (s != null && s < worst) {
                worst = s;
                best = def[1];
            }
        }
        return best;
    }

    private static String worstScore(JSONArray cats) {
        double worst = 101;
        for (String[] def : Ui.CATEGORIES) {
            JSONObject c = findCat(cats, def[0]);
            if (c == null) {
                continue;
            }
            Double s = numberOrNull(c.opt("score"));
            if (s != null && s < worst) {
                worst = s;
            }
        }
        return worst > 100 ? "—" : String.format(Locale.US, "%.1f", worst);
    }

    private static String scoreColor(double score, boolean scored) {
        if (!scored) {
            return "#938F99";
        }
        if (score >= 85) {
            return "#B6F09C";
        }
        if (score >= 60) {
            return "#F9E2AF";
        }
        return "#FFB4AB";
    }

    private static void add(List<String> list, String v) {
        if (!list.contains(v)) {
            list.add(v);
        }
    }

    private static String joinLabels(List<String[]> blind) {
        List<String> names = new ArrayList<>();
        for (String[] b : blind) {
            names.add(b[1]);
        }
        return String.join("、", names);
    }

    private static Double numberOrNull(Object raw) {
        return raw instanceof Number ? ((Number) raw).doubleValue() : null;
    }

    // ================================================================ 事实取数

    private static String fact(JSONObject facts, String key) {
        if (facts == null) {
            return "";
        }
        Object v = facts.opt(key);
        if (v == null || JSONObject.NULL.equals(v)) {
            return "";
        }
        return String.valueOf(v);
    }

    private static String actualCert(JSONObject facts) {
        if (facts == null) {
            return "";
        }
        JSONArray a = facts.optJSONArray("cert.install");
        if (a == null) {
            a = facts.optJSONArray("cert.signing");
        }
        if (a == null || a.length() == 0) {
            return "";
        }
        return a.optString(0, "");
    }

    /** ③ 的签名一行：期望值烘在 assets 里，所以 App 自己也能比。 */
    private static String certCompare(JSONObject facts) {
        String expect = BuildInfo.expectedCertSha256;
        String actual = actualCert(facts);
        String verdict;
        if (expect == null || expect.isEmpty()) {
            verdict = "构建期没有烘进期望值（dev 包），无法比对";
        } else if (actual.isEmpty()) {
            verdict = "没取到签名证书";
        } else if (expect.equalsIgnoreCase(actual)) {
            verdict = "<span class=\"good\">一致</span>";
        } else {
            verdict = "<strong>不一致</strong>";
        }
        return "期望：<code>" + esc(shortHash(expect)) + "</code><br>实测：<code>" + esc(shortHash(actual))
                + "</code><br>结论：" + verdict;
    }

    private static String deviceLine(JSONObject device) {
        if (device == null) {
            return "设备未知";
        }
        return device.optString("model", "?") + " / Android " + device.optString("release", "?")
                + " (API " + device.optInt("sdk", 0) + ")";
    }

    /** 包名（③ 与页头都要用）。 */
    private static String pkgName(JSONObject app) {
        return app == null ? "—" : orDash(app.optString("package", ""));
    }

    /**
     * 采集时间：report 里是 UTC 的 ISO 串（{@code 2026-11-10T08:21:33Z}），
     * 页头给用户看要转成本地时区的「2026-11-10 18:21」。
     */
    private static String collectedText(JSONObject run) {
        String iso = run == null ? "" : run.optString("collectedAt", "");
        if (iso == null || iso.isEmpty()) {
            return "—";
        }
        try {
            java.text.SimpleDateFormat in =
                    new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
            in.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
            java.util.Date d = in.parse(iso);
            java.text.SimpleDateFormat out =
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
            return out.format(d);
        } catch (Throwable t) {
            return iso;
        }
    }

    private static String shortHash(String s) {
        if (s == null || s.isEmpty()) {
            return "—";
        }
        return s.length() <= 16 ? s : s.substring(0, 16) + "…";
    }

    private static String shortText(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    private static String orDash(String s) {
        return s == null || s.isEmpty() ? "—" : s;
    }

    // ================================================================ 输出小工具

    private static String kpi(String num, String color, String label, String hint) {
        return "<div class=\"kpi\"><div class=\"n\" style=\"color:" + color + "\">" + esc(num) + "</div>"
                + "<div class=\"k\">" + esc(label) + "</div><div class=\"hint\">" + esc(hint) + "</div></div>\n";
    }

    /** 一律两列的「字段名 | 值」表；值里允许已生成的 HTML 片段。 */
    private static String table2(String[][] rows) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div class=\"scrollx\"><table class=\"kv\"><tbody>\n");
        for (String[] r : rows) {
            sb.append("<tr><th>").append(esc(r[0])).append("</th><td>").append(r[1]).append("</td></tr>\n");
        }
        sb.append("</tbody></table></div>");
        return sb.toString();
    }

    private static String badge(String verdict) {
        int color = Ui.verdictColor(verdict);
        return "<span class=\"badge\" style=\"color:" + hex(color) + ";background:" + rgba(color, 0.16) + "\">"
                + Ui.verdictZh(verdict) + "（" + esc(verdict) + "）</span>";
    }

    private static String hex(int c) {
        return String.format("#%06X", 0xFFFFFF & c);
    }

    private static String rgba(int c, double alpha) {
        return String.format(Locale.US, "rgba(%d,%d,%d,%.2f)",
                (c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF, alpha);
    }

    /** HTML 转义 + 洗掉 http(s) 字样（自检要求：正文里不许出现外链）。 */
    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&#39;");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString().replace("https://", "hxxps://").replace("http://", "hxxp://");
    }

    /** 文案里的 Markdown 行内代码 → {@code <code>}（与 App 里 Ui.md 的语义一致）。 */
    private static String md(String s) {
        String e = esc(s);
        if (e.indexOf('`') < 0) {
            return e;
        }
        StringBuilder sb = new StringBuilder(e.length() + 16);
        boolean open = false;
        for (int i = 0; i < e.length(); i++) {
            char c = e.charAt(i);
            if (c == '`') {
                sb.append(open ? "</code>" : "<code>");
                open = !open;
                continue;
            }
            sb.append(c);
        }
        if (open) {
            sb.append("</code>");
        }
        return sb.toString();
    }

    // ================================================================ 内联样式（M3 深色，与 App UI 同一套 token）

    private static String css() {
        return ""
                + "*{box-sizing:border-box}"
                + "body{margin:0;background:#141218;color:#E6E0E9;"
                + "font:14px/1.65 -apple-system,'Noto Sans CJK SC','Source Han Sans SC',sans-serif;"
                + "-webkit-text-size-adjust:100%}"
                + ".wrap{max-width:860px;margin:0 auto;padding:18px 14px 40px}"
                + ".topbar{padding:6px 2px 14px}"
                + ".brand{display:flex;align-items:center;gap:6px;color:#CAC4D0;font-size:11px;"
                + "letter-spacing:.12em;text-transform:uppercase}"
                + ".dot{width:8px;height:8px;border-radius:50%;background:#D0BCFF;display:inline-block}"
                + ".sep{opacity:.5}"
                + ".eyebrow{color:#49454F;letter-spacing:.06em;font-size:9px;opacity:.9}"
                + "h1{font-size:24px;margin:6px 0 4px;letter-spacing:-.02em;color:#E6E0E9}"
                + ".meta{color:#938F99;font-size:12px;margin:2px 0}"
                + ".runchip{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#938F99;background:#2B2930;border-radius:6px;padding:1px 6px}"
                + ".hero{background:#1D1B20;border-radius:24px;padding:18px;margin:6px 0 18px}"
                + ".scorebox{display:flex;align-items:baseline;gap:6px}"
                + ".score-num{font-size:48px;font-weight:500;letter-spacing:-.02em}"
                + ".score-den{color:#938F99;font-size:13px}"
                + ".score-cap{color:#CAC4D0;font-size:12px;margin-top:6px}"
                + ".chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}"
                + ".chip{background:#2B2930;color:#CAC4D0;border-radius:999px;padding:4px 10px;font-size:11px}"
                + ".chip.primary{background:#4F378B;color:#EADDFF}"
                + ".chip.tampered{background:rgba(255,180,171,.16);color:#FFB4AB}"
                + "section{margin:26px 0 0}"
                + "h2{font-size:17px;font-weight:500;margin:0 0 10px;padding-top:14px;border-top:1px solid #49454F}"
                + "h3.sub{font-size:14px;font-weight:500;color:#D0BCFF;margin:18px 0 6px}"
                + "p{margin:8px 0;color:#CAC4D0}"
                + "p.note{color:#938F99;font-size:12px}"
                + "p.ok{color:#B6F09C;font-size:13px}"
                + "strong{color:#E6E0E9;font-weight:600}"
                + "em{color:#938F99;font-style:normal}"
                + "code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.92em;"
                + "background:#2B2930;color:#EADDFF;border-radius:6px;padding:1px 4px;word-break:normal;overflow-wrap:anywhere}"
                + "pre{background:#1D1B20;border-radius:14px;padding:12px;overflow-x:auto;color:#CAC4D0;"
                + "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.7;white-space:pre}"
                + ".kpis{display:flex;gap:10px;flex-wrap:wrap}"
                + ".kpi{flex:1 1 30%;min-width:150px;background:#1D1B20;border-radius:16px;padding:14px}"
                + ".kpi .n{font-size:26px;font-weight:500;letter-spacing:-.02em}"
                + ".kpi .k{color:#CAC4D0;font-size:12px;margin-top:2px}"
                + ".kpi .hint{color:#938F99;font-size:11px;margin-top:6px}"
                + ".card{background:#1D1B20;border-radius:16px;padding:4px 14px;margin:10px 0}"
                + ".scrollx{overflow-x:auto}"
                + "table{width:100%;border-collapse:collapse;font-size:13px}"
                + "table.kv th{width:34%;text-align:left;color:#938F99;font-weight:400;padding:9px 8px 9px 0;"
                + "vertical-align:top;border-bottom:1px solid #2B2930;white-space:nowrap}"
                + "table.kv td{color:#CAC4D0;padding:9px 0;border-bottom:1px solid #2B2930;word-break:break-word}"
                + "table.kv tr:last-child th,table.kv tr:last-child td{border-bottom:0}"
                + "table th,table td{text-align:left;padding:8px 6px;border-bottom:1px solid #2B2930;"
                + "color:#CAC4D0;vertical-align:top}"
                + ".badge{display:inline-block;border-radius:999px;padding:1px 8px;font-size:11px;"
                + "white-space:nowrap;font-weight:500}"
                + ".flag{background:#1D1B20;border-radius:16px;padding:14px;margin:12px 0;border-left:3px solid #FFB4AB}"
                + ".flag.blind{border-left-color:#F9E2AF}"
                + ".flag h4{margin:0 0 8px;font-size:14px;font-weight:500;color:#E6E0E9}"
                + ".flag p{margin:6px 0;font-size:13px}"
                + ".tierc{color:#938F99;font-size:11px}"
                + ".ev{color:#938F99;font-size:12px;word-break:break-all}"
                + ".good{color:#B6F09C}"
                + ".grp{color:#D0BCFF;font-size:12px;letter-spacing:.03em;margin:12px 0 4px}"
                + ".vec{padding:8px 0;border-bottom:1px solid #2B2930}"
                + ".vec:last-child{border-bottom:0}"
                + ".act{font-size:14px;font-weight:500;color:#E6E0E9;margin:12px 0 2px}"
                + ".foot{color:#49454F;font-size:11px;margin-top:28px;text-align:center}";
    }
}
