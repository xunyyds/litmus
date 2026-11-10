package io.litmus.core;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 本地摘要评分。契约见 docs/04-契约.md §2 与 docs/03-评分模型.md。
 *
 * <p><b>CLI 是权威</b>：这里只给 App 界面一个即时数字，CLI 会用自己的实现重算一遍
 * （含基线归一与盲区判定）。两边公式必须一致，改公式请同时改 {@code cli/litmus_score.py}。
 */
public final class Score {

    /** 六类聚合权重，契约 §2.1。 */
    private static final Map<String, Double> CATEGORY_WEIGHT = new LinkedHashMap<>();

    static {
        CATEGORY_WEIGHT.put("runtime-integrity", 0.24);
        CATEGORY_WEIGHT.put("injection", 0.22);
        CATEGORY_WEIGHT.put("package-integrity", 0.20);
        CATEGORY_WEIGHT.put("privilege", 0.14);
        CATEGORY_WEIGHT.put("virtualization", 0.10);
        CATEGORY_WEIGHT.put("environment", 0.10);
    }

    private Score() {
    }

    /**
     * @param signals Array of signal objects（字段见契约 §4.1）
     * @return {@code {"total","clean","suspect","tampered","unknown","error","flaky","score","categories":[…]}}
     */
    public static JSONObject summarize(JSONArray signals) {
        int clean = 0, suspect = 0, tampered = 0, unknown = 0, error = 0, flaky = 0;

        Map<String, double[]> acc = new LinkedHashMap<>();  // category -> {pollutedWeight, countedWeight}
        for (String k : CATEGORY_WEIGHT.keySet()) {
            acc.put(k, new double[]{0d, 0d});
        }

        JSONObject catCounts = new JSONObject();
        for (int i = 0; i < signals.length(); i++) {
            JSONObject s = signals.optJSONObject(i);
            if (s == null) {
                continue;
            }
            String verdict = s.optString("verdict", Signal.UNKNOWN);
            String cat = s.optString("category", "");
            int w = Math.max(1, Math.min(5, s.optInt("weight", 3)));

            switch (verdict) {
                case Signal.CLEAN: clean++; break;
                case Signal.SUSPECT: suspect++; break;
                case Signal.TAMPERED: tampered++; break;
                case Signal.ERROR: error++; break;
                case Signal.FLAKY: flaky++; break;
                default: unknown++; break;
            }

            boolean countable = !Signal.UNKNOWN.equals(verdict)
                    && !Signal.ERROR.equals(verdict)
                    && !Signal.FLAKY.equals(verdict);
            if (!countable || !acc.containsKey(cat)) {
                continue;
            }
            double[] a = acc.get(cat);
            a[1] += w;
            if (Signal.TAMPERED.equals(verdict)) {
                a[0] += w;
            } else if (Signal.SUSPECT.equals(verdict)) {
                a[0] += w * 0.5;
            }
            try {
                JSONObject c = catCounts.optJSONObject(cat);
                if (c == null) {
                    c = new JSONObject();
                    c.put("tampered", 0);
                    c.put("suspect", 0);
                    c.put("clean", 0);
                    c.put("total", 0);
                    catCounts.put(cat, c);
                }
                c.put("total", c.optInt("total") + 1);
                if (Signal.TAMPERED.equals(verdict)) {
                    c.put("tampered", c.optInt("tampered") + 1);
                } else if (Signal.SUSPECT.equals(verdict)) {
                    c.put("suspect", c.optInt("suspect") + 1);
                } else if (Signal.CLEAN.equals(verdict)) {
                    c.put("clean", c.optInt("clean") + 1);
                }
                // 契约外的 verdict 不归类：宁可少计数，也不要把它算成 CLEAN 抬高分数。
                // 这类值只可能来自实现 bug，出现时应当显眼地「不干净也不脏」，而不是悄悄加分。
            } catch (Throwable ignored) {
            }
        }

        JSONArray categories = new JSONArray();
        double weightedSum = 0d;
        double weightTotal = 0d;
        for (Map.Entry<String, Double> e : CATEGORY_WEIGHT.entrySet()) {
            String cat = e.getKey();
            double a = e.getValue();
            double[] v = acc.get(cat);
            double counted = v[1];
            double catScore = counted <= 0 ? -1d : 100d * (1d - v[0] / counted);
            if (catScore >= 0) {
                weightedSum += a * catScore;
                weightTotal += a;
            }
            JSONObject c = catCounts.optJSONObject(cat);
            JSONObject o = new JSONObject();
            try {
                o.put("id", cat);
                o.put("weight", a);
                o.put("score", catScore < 0 ? JSONObject.NULL : round1(catScore));
                o.put("tampered", c == null ? 0 : c.optInt("tampered"));
                o.put("suspect", c == null ? 0 : c.optInt("suspect"));
                o.put("clean", c == null ? 0 : c.optInt("clean"));
                o.put("total", c == null ? 0 : c.optInt("total"));
            } catch (Throwable ignored) {
            }
            categories.put(o);
        }

        double score = weightTotal <= 0 ? -1d : weightedSum / weightTotal;

        JSONObject out = new JSONObject();
        try {
            out.put("total", signals.length());
            out.put("clean", clean);
            out.put("suspect", suspect);
            out.put("tampered", tampered);
            out.put("unknown", unknown);
            out.put("error", error);
            out.put("flaky", flaky);
            out.put("score", score < 0 ? JSONObject.NULL : round1(score));
            out.put("categories", categories);
        } catch (Throwable ignored) {
        }
        return out;
    }

    public static double round1(double v) {
        return Math.round(v * 10d) / 10d;
    }
}
