package io.litmus.core;

/**
 * 单条检测结论。不可变。
 *
 * <p>契约见 docs/04-契约.md §1.1。一个 {@link Probe} 只产出一条 Signal。
 */
public final class Signal {

    /** 未发现篡改。 */
    public static final String CLEAN = "CLEAN";
    /** 有痕迹，但证据不足以下定论。 */
    public static final String SUSPECT = "SUSPECT";
    /** 确认被改。 */
    public static final String TAMPERED = "TAMPERED";
    /** 本设备 / 本版本测不了（不扣分，单独统计）。 */
    public static final String UNKNOWN = "UNKNOWN";
    /** 探针自身异常（不扣分，单独统计）。 */
    public static final String ERROR = "ERROR";
    /** 多次采样结论不一致（不扣分，标记该检测不可靠）。 */
    public static final String FLAKY = "FLAKY";

    public final String id;
    public final String category;
    public final String verdict;
    public final double confidence;
    public final int weight;
    public final String tier;
    public final String evidence;
    public final long ms;

    public Signal(String id, String category, String verdict, double confidence,
                  int weight, String tier, String evidence, long ms) {
        this.id = id;
        this.category = category;
        this.verdict = verdict;
        this.confidence = clamp(confidence);
        this.weight = weight < 1 ? 1 : (weight > 5 ? 5 : weight);
        this.tier = tier == null ? "B" : tier;
        this.evidence = trim(evidence);
        this.ms = ms;
    }

    /** 污染度：参与加权的扣分值。 */
    public double pollution() {
        switch (verdict) {
            case TAMPERED:
                return 1.0;
            case SUSPECT:
                return 0.5;
            default:
                return 0.0;
        }
    }

    /** 是否计入加权分母。UNKNOWN / ERROR / FLAKY 一律不计。 */
    public boolean countable() {
        return !UNKNOWN.equals(verdict) && !ERROR.equals(verdict) && !FLAKY.equals(verdict);
    }

    /** 是否算「被抓到」。CLI 的盲区判定用这个。 */
    public boolean detected() {
        return TAMPERED.equals(verdict);
    }

    private static double clamp(double v) {
        if (Double.isNaN(v)) {
            return 0.0;
        }
        return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v);
    }

    private static String trim(String s) {
        if (s == null) {
            return "";
        }
        String one = s.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
        return one.length() <= 300 ? one : one.substring(0, 297) + "...";
    }

    @Override
    public String toString() {
        return id + "=" + verdict + "(" + confidence + ") " + evidence;
    }
}
