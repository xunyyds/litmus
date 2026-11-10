// Litmus 检测内核 · native 探针
//
// 契约：docs/04-契约.md §4.5 —— snapshot() 返回单个 JSON 对象字符串。
// 分工：本文件只做**机械取证**，不做判定。判定在 io.litmus.core.probes 里。
//
// 已实现：maps 统计（anonExec/rwx/memfd/deleted 精化）/ TracerPid / 线程名 / vdso 大小 /
//         syscall 时延 / inline hook 字节比对 / GOT 落点检查
//
// 新增字段全部是「加子对象 / 加子键」，已有字段名一个都没动；见文件末尾的字段清单注释。

#include <jni.h>

#include <android/log.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "elf_scan.h"

#define LOG_TAG "litmus-probe"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

constexpr const char *kVersion = "0.2.0";

// 单次 snapshot 的时间切分（总目标 < 40ms）
constexpr long long kInlineBudgetMs = 25;  // 契约要求 inlineHook 扫描 < 30ms
constexpr long long kGotBudgetMs = 7;

// ------------------------------------------------------------------ JSON 辅助

std::string jsonEscape(const std::string &in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string quote(const std::string &s) { return "\"" + jsonEscape(s) + "\""; }

std::string num(long long v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", v);
    return std::string(buf);
}

std::string strArray(const std::vector<std::string> &v, size_t limit = 8) {
    std::string out = "[";
    for (size_t i = 0; i < v.size() && i < limit; i++) {
        if (i) out += ",";
        out += quote(v[i]);
    }
    out += "]";
    return out;
}

// {count, samples}——契约里已有的形态，原样保留。
std::string countSamplesJson(int count, const std::vector<std::string> &samples) {
    return "{\"count\":" + num(count) + ",\"samples\":" + strArray(samples) + "}";
}

// {count, samples, so, dex, apk}——memfd / deleted 的精化计数（只加键，不改已有键）。
std::string countSamplesTypedJson(int count, const std::vector<std::string> &samples, int so,
                                  int dex, int apk) {
    return "{\"count\":" + num(count) + ",\"samples\":" + strArray(samples) +
           ",\"so\":" + num(so) + ",\"dex\":" + num(dex) + ",\"apk\":" + num(apk) + "}";
}

// 顶层对象拼装器：key() 自动处理逗号，从结构上消灭尾逗号。
class JObj {
  public:
    JObj() {
        s_.reserve(4096);
        s_ += '{';
    }

    JObj &key(const char *k) {
        if (s_.size() > 1) s_ += ',';
        s_ += '"';
        s_ += k;
        s_ += "\":";
        return *this;
    }

    JObj &raw(const std::string &v) {
        s_ += v;
        return *this;
    }

    std::string finish() {
        s_ += '}';
        return s_;
    }

  private:
    std::string s_;
};

// ------------------------------------------------------------------ 文件读取

bool readFile(const char *path, std::string &out, size_t cap = 4u * 1024 * 1024) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<size_t>(n));
        if (out.size() > cap) break;
    }
    close(fd);
    return true;
}

std::vector<std::string> splitLines(const std::string &s) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < s.size()) {
        size_t pos = s.find('\n', start);
        if (pos == std::string::npos) {
            lines.push_back(s.substr(start));
            break;
        }
        lines.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return lines;
}

// ------------------------------------------------------------------ /proc/self/status

int readTracerPid() {
    std::string status;
    if (!readFile("/proc/self/status", status, 256 * 1024)) return -1;
    for (const auto &line : splitLines(status)) {
        if (line.compare(0, 9, "TracerPid") == 0) {
            size_t colon = line.find(':');
            if (colon == std::string::npos) return -1;
            return atoi(line.c_str() + colon + 1);
        }
    }
    return -1;
}

// ------------------------------------------------------------------ maps

bool parseMapsLine(const std::string &line, litmus::MapRegion &r) {
    unsigned long long start = 0, end = 0, off = 0, inode = 0;
    char perms[8] = {0};
    char dev[16] = {0};
    int pathOff = 0;
    int n = sscanf(line.c_str(), "%llx-%llx %7s %llx %15s %llu %n", &start, &end, perms, &off,
                   dev, &inode, &pathOff);
    if (n < 6) return false;
    r.start = start;
    r.end = end;
    r.offset = off;
    r.perms = perms;
    r.readable = r.perms.find('r') != std::string::npos;
    r.writable = r.perms.find('w') != std::string::npos;
    r.executable = r.perms.find('x') != std::string::npos;
    // dev 是 "major:minor"（十六进制），inode 是十进制；两个一起用来确认
    // 「磁盘上这个路径还是被 mmap 的那一个文件」，避免包更新/overlay 造成的假阳性。
    unsigned int dmaj = 0, dmin = 0;
    if (sscanf(dev, "%x:%x", &dmaj, &dmin) == 2) {
        r.dev = (static_cast<uint64_t>(dmaj) << 32) | static_cast<uint64_t>(dmin);
    }
    r.ino = inode;
    r.path.clear();
    if (pathOff > 0 && static_cast<size_t>(pathOff) < line.size()) {
        r.path = line.substr(static_cast<size_t>(pathOff));
        size_t b = r.path.find_first_not_of(' ');
        r.path = (b == std::string::npos) ? std::string() : r.path.substr(b);
    }
    r.deleted = r.path.size() > 10 && r.path.compare(r.path.size() - 10, 10, " (deleted)") == 0;
    return true;
}

std::string hexRange(uint64_t s, uint64_t e) {
    char buf[48];
    snprintf(buf, sizeof(buf), "%llx-%llx", static_cast<unsigned long long>(s),
             static_cast<unsigned long long>(e));
    return buf;
}

struct MapsStats {
    int anonExecCount = 0;
    long long anonExecBytes = 0;
    std::vector<std::string> anonExecSamples;
    int rwxCount = 0;
    std::vector<std::string> rwxSamples;
    int memfdCount = 0;
    std::vector<std::string> memfdSamples;
    int memfdSo = 0;
    int memfdDex = 0;
    int memfdApk = 0;
    int deletedCount = 0;
    std::vector<std::string> deletedSamples;
    int deletedSo = 0;
    int deletedDex = 0;
    int deletedApk = 0;
    long long vdsoSize = 0;
};

struct MapsReport {
    MapsStats st;
    std::vector<litmus::MapRegion> regions;  // 全量，供 ELF 扫描用
};

bool pathHas(const std::string &p, const char *token) { return p.find(token) != std::string::npos; }

// 只读一次 /proc/self/maps：既算统计，也留全量记录给 inline hook / GOT 扫描。
MapsReport scanMaps() {
    MapsReport rep;
    std::string content;
    if (!readFile("/proc/self/maps", content)) return rep;
    rep.regions.reserve(512);

    const auto &lines = splitLines(content);
    MapsStats &st = rep.st;
    for (const auto &line : lines) {
        litmus::MapRegion r;
        if (!parseMapsLine(line, r)) continue;
        rep.regions.push_back(r);

        const bool x = r.executable;
        const bool w = r.writable;

        if (x && w) {
            st.rwxCount++;
            if (st.rwxSamples.size() < 8) st.rwxSamples.push_back(hexRange(r.start, r.end) + " " + r.perms);
        }

        if (x && r.path.empty()) {
            st.anonExecCount++;
            st.anonExecBytes += static_cast<long long>(r.end - r.start);
            if (st.anonExecSamples.size() < 8)
                st.anonExecSamples.push_back(hexRange(r.start, r.end) + " " + r.perms);
        }

        if (x && pathHas(r.path, "memfd:")) {
            st.memfdCount++;
            if (pathHas(r.path, ".so")) st.memfdSo++;
            if (pathHas(r.path, "dex")) st.memfdDex++;
            if (pathHas(r.path, ".apk")) st.memfdApk++;
            if (st.memfdSamples.size() < 8) st.memfdSamples.push_back(r.path.substr(0, 100));
        }

        if (r.deleted) {
            st.deletedCount++;
            if (pathHas(r.path, ".so")) st.deletedSo++;
            if (pathHas(r.path, "dex")) st.deletedDex++;
            if (pathHas(r.path, ".apk")) st.deletedApk++;
            if (st.deletedSamples.size() < 8) st.deletedSamples.push_back(r.path.substr(0, 120));
        }

        if (r.path == "[vdso]") st.vdsoSize = static_cast<long long>(r.end - r.start);
    }
    return rep;
}

// ------------------------------------------------------------------ 线程名

std::vector<std::string> readThreadNames(int *countOut) {
    std::vector<std::string> names;
    int count = 0;
    DIR *d = opendir("/proc/self/task");
    if (!d) {
        if (countOut) *countOut = -1;
        return names;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        count++;
        std::string commPath = std::string("/proc/self/task/") + ent->d_name + "/comm";
        std::string comm;
        if (readFile(commPath.c_str(), comm, 4096) && names.size() < 256) {
            while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
            names.push_back(comm);
        }
    }
    closedir(d);
    if (countOut) *countOut = count;
    return names;
}

// ------------------------------------------------------------------ syscall 时延
//
// 用 openat("/dev/null") 做基准：必走真实 syscall，不进 vDSO。
// hook 掉 libc open 会把这段时延抬高/抖动，是框架无关的行为侧不变量。

struct TimingStats {
    int n = 0;
    long long medianNs = 0;
    long long p99Ns = 0;
    long long jitterNs = 0;
};

long long nowNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long long>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
}

int cmpLongLong(const void *a, const void *b) {
    long long x = *static_cast<const long long *>(a);
    long long y = *static_cast<const long long *>(b);
    return x < y ? -1 : (x > y ? 1 : 0);
}

TimingStats measureSyscall(int iterations) {
    TimingStats st;
    if (iterations <= 0) return st;
    std::vector<long long> samples;
    samples.reserve(static_cast<size_t>(iterations));
    for (int i = 0; i < iterations; i++) {
        long long t0 = nowNs();
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
        long long t1 = nowNs();
        samples.push_back(t1 - t0);
    }
    qsort(samples.data(), samples.size(), sizeof(long long), cmpLongLong);
    st.n = static_cast<int>(samples.size());
    st.medianNs = samples[samples.size() / 2];
    st.p99Ns = samples[(samples.size() * 99) / 100];
    st.jitterNs = st.p99Ns - st.medianNs;
    return st;
}

// ------------------------------------------------------------------ 汇总

// 契约 §4.5 的字段一个不少；新增内容全部是「子对象内的新键」，见 §4.5 扩展说明。
std::string buildSnapshotJson() {
    const long long t0 = nowNs() / 1000000LL;

    const int tracerPid = readTracerPid();
    const MapsReport maps = scanMaps();
    int threadCount = -1;
    const std::vector<std::string> threadNames = readThreadNames(&threadCount);
    const TimingStats tm = measureSyscall(200);  // 先测时延，避免被下面的 mmap 搅热

    const litmus::InlineScanResult ih = litmus::scanInlineHooks(maps.regions, kInlineBudgetMs);
    const litmus::GotScanResult gc = litmus::checkGotPlt(maps.regions, kGotBudgetMs);

    const MapsStats &st = maps.st;

    JObj j;
    j.key("ok").raw("true");
    j.key("abi").raw(quote(
#if defined(__aarch64__)
        "arm64-v8a"
#elif defined(__arm__)
        "armeabi-v7a"
#elif defined(__x86_64__)
        "x86_64"
#elif defined(__i386__)
        "x86"
#else
        "unknown"
#endif
        ));
    j.key("pid").raw(num(static_cast<long long>(getpid())));
    j.key("tracerPid").raw(num(tracerPid));
    j.key("vdsoSize").raw(num(st.vdsoSize));

    j.key("anonExec").raw("{\"count\":" + num(st.anonExecCount) + ",\"bytes\":" +
                          num(st.anonExecBytes) + ",\"samples\":" + strArray(st.anonExecSamples) +
                          "}");
    j.key("rwx").raw(countSamplesJson(st.rwxCount, st.rwxSamples));
    j.key("memfd").raw(countSamplesTypedJson(st.memfdCount, st.memfdSamples, st.memfdSo,
                                             st.memfdDex, st.memfdApk));
    j.key("deleted").raw(countSamplesTypedJson(st.deletedCount, st.deletedSamples, st.deletedSo,
                                               st.deletedDex, st.deletedApk));
    j.key("threads").raw("{\"count\":" + num(threadCount) + ",\"names\":" +
                         strArray(threadNames, 64) + "}");

    // inlineHook：libs=真正比对了符号的 .so 数，tramp=命中里带经典跳板形态的个数，
    // skipped=打不开/解析失败的 .so 数，truncated=1 表示撞上限（结果不完整），ms=耗时
    j.key("inlineHook").raw(
        "{\"scanned\":" + num(ih.scanned) + ",\"hits\":" + num(ih.hits) +
        ",\"samples\":" + strArray(ih.samples) + ",\"libs\":" + num(ih.libs) +
        ",\"tramp\":" + num(ih.tramp) + ",\"skipped\":" + num(ih.skipped) +
        ",\"truncated\":" + num(ih.truncated) + ",\"ms\":" + num(ih.ms) + "}");

    // gotCheck：plt=.rela.plt 条目数，nulls=值为 0 的槽（弱符号，不判定），ms=耗时
    j.key("gotCheck").raw(
        "{\"scanned\":" + num(gc.scanned) + ",\"bad\":" + num(gc.bad) +
        ",\"samples\":" + strArray(gc.samples) + ",\"plt\":" + num(gc.plt) +
        ",\"nulls\":" + num(gc.nulls) + ",\"ms\":" + num(gc.ms) + "}");

    j.key("timing").raw("{\"n\":" + num(tm.n) + ",\"medianNs\":" + num(tm.medianNs) +
                        ",\"p99Ns\":" + num(tm.p99Ns) + ",\"jitterNs\":" + num(tm.jitterNs) + "}");

    // 附加：本次 snapshot 的自身耗时（不参与判定，只给 CLI 复核性能用）
    j.key("elapsedMs").raw(num(nowNs() / 1000000LL - t0));

    return j.finish();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL Java_io_litmus_core_NativeBridge_version(JNIEnv *env, jclass) {
    return env->NewStringUTF(kVersion);
}

extern "C" JNIEXPORT jstring JNICALL Java_io_litmus_core_NativeBridge_snapshot(JNIEnv *env,
                                                                             jclass) {
    std::string json;
    // 任何异常路径都不能把 Java 侧炸掉：拼装失败就回一个最小合法 JSON。
    json = buildSnapshotJson();
    if (json.empty() || json[0] != '{') {
        json = "{\"ok\":false,\"error\":\"snapshot build failed\"}";
    }
    return env->NewStringUTF(json.c_str());
}
