package io.litmus.core;

/**
 * 一条检测向量。
 *
 * <p>契约见 docs/04-契约.md §1.2。实现类放在 {@code io.litmus.core.probes} 下，按类别分文件。
 *
 * <p>硬约束：
 * <ul>
 *   <li>一个 Probe 只能 emit 一次；</li>
 *   <li>不得把异常抛给 Runner（Runner 会兜底转成 ERROR，但那样就丢失了 evidence）；</li>
 *   <li>不得阻塞超过 50ms（rt.timing 除外）。</li>
 * </ul>
 */
public interface Probe {

    /** 稳定 id，见 docs/04-契约.md §3。 */
    String id();

    /** 六类之一，必须与 id 前缀一致。 */
    String category();

    /** 1..5，越大越重要。默认 3。 */
    default int weight() {
        return 3;
    }

    /**
     * 证据强度：
     * <ul>
     *   <li>A = 不变量/密码学，可以下 TAMPERED；</li>
     *   <li>B = 交叉视图，可以下 TAMPERED 但应有 2 条以上证据；</li>
     *   <li>C = 特征匹配，<b>只允许 SUSPECT</b>。</li>
     * </ul>
     */
    default String tier() {
        return "B";
    }

    void run(LitmusContext ctx, Sink sink) throws Exception;

    /** 结论出口。 */
    interface Sink {
        void emit(String verdict, double confidence, String evidence);

        default void clean(String ev) {
            emit(Signal.CLEAN, 0.95, ev);
        }

        default void clean(String ev, double conf) {
            emit(Signal.CLEAN, conf, ev);
        }

        default void suspect(String ev, double conf) {
            emit(Signal.SUSPECT, conf, ev);
        }

        default void tampered(String ev, double conf) {
            emit(Signal.TAMPERED, conf, ev);
        }

        default void unknown(String ev) {
            emit(Signal.UNKNOWN, 0.0, ev);
        }

        default void error(String ev) {
            emit(Signal.ERROR, 0.0, ev);
        }
    }
}
