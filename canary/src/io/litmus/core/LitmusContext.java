package io.litmus.core;

import android.content.Context;

/**
 * 一次检测运行的上下文。
 *
 * <p>契约见 docs/04-契约.md §1.3。{@code appSnap} / {@code nat} 都是**一次采样、全体复用**，
 * 保证同一轮里所有向量看到的是同一时刻的世界（否则 rt.* 系列会互相矛盾）。
 */
public final class LitmusContext {

    public final Context app;
    public final AppSnapshot appSnap;
    public final NativeSnapshot nat;
    public final Facts facts;

    public LitmusContext(Context app, AppSnapshot appSnap, NativeSnapshot nat, Facts facts) {
        this.app = app;
        this.appSnap = appSnap;
        this.nat = nat;
        this.facts = facts == null ? new Facts() : facts;
    }

    public boolean hasNative() {
        return nat != null && nat.ok;
    }
}
