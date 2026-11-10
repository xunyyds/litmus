package io.litmus.core;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Collection;
import java.util.TreeMap;

/**
 * 原始事实袋子。值是「观测值」，不是「判定」。
 *
 * <p>契约见 docs/04-契约.md §4.1 的 {@code facts} 字段。CLI 平面靠这些值做进程外复核
 * （典型：pkg.codepath.hash、pkg.zip.fingerprint —— 期望值烘不进 APK 自身，只能由 CLI 判）。
 */
public final class Facts {

    private final TreeMap<String, Object> map = new TreeMap<>();

    public Facts put(String key, Object value) {
        if (key != null && value != null) {
            map.put(key, value);
        }
        return this;
    }

    public boolean has(String key) {
        return map.containsKey(key);
    }

    public Object get(String key) {
        return map.get(key);
    }

    public Collection<String> keys() {
        return map.keySet();
    }

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        for (java.util.Map.Entry<String, Object> e : map.entrySet()) {
            try {
                Object v = e.getValue();
                if (v instanceof Collection) {
                    JSONArray a = new JSONArray();
                    for (Object item : (Collection<?>) v) {
                        a.put(item);
                    }
                    o.put(e.getKey(), a);
                } else {
                    o.put(e.getKey(), v);
                }
            } catch (Throwable ignored) {
                // 事实字段写失败不影响整体
            }
        }
        return o;
    }
}
