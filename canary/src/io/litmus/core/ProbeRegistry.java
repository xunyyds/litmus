package io.litmus.core;

import io.litmus.core.probes.EnvironmentProbes;
import io.litmus.core.probes.InjectionProbes;
import io.litmus.core.probes.PackageIntegrityProbes;
import io.litmus.core.probes.PrivilegeProbes;
import io.litmus.core.probes.RuntimeIntegrityProbes;
import io.litmus.core.probes.VirtualizationProbes;

import java.util.ArrayList;
import java.util.List;

/**
 * 向量注册表。契约见 docs/04-契约.md §1.4 / §1.5。
 *
 * <p>顺序 = 报告里的顺序；按类别排列，方便人读。新增类别才需要动这里。
 */
public final class ProbeRegistry {

    private ProbeRegistry() {
    }

    public static List<Probe> all() {
        List<Probe> out = new ArrayList<>(64);
        out.addAll(RuntimeIntegrityProbes.list());
        out.addAll(InjectionProbes.list());
        out.addAll(PackageIntegrityProbes.list());
        out.addAll(PrivilegeProbes.list());
        out.addAll(VirtualizationProbes.list());
        out.addAll(EnvironmentProbes.list());
        return out;
    }

    public static int count() {
        return all().size();
    }
}
