// Litmus 检测内核 · 内存侧不变量扫描（与框架无关）
//
// 契约：docs/04-契约.md §4.5 的 inlineHook / gotCheck 两个子对象。
// 本模块只产出「事实」（扫了多少、命中多少、样本），不做判定。
//
// 设计要点：
//   1. 不找任何框架特征。只问「运行时字节 vs 磁盘字节」是否一致 —— 这是 tier A 的不变量。
//   2. 只读：open+mmap(PROT_READ) 磁盘文件，memcpy 读自己进程的内存；不 ptrace、不写别人。
//   3. 所有循环都有硬上限 + 单调时钟预算，超时立刻带着已有结果返回。
//   4. 不用异常（构建带 -fno-exceptions）；任何失败都退化为「少扫一个库」。

#ifndef LITMUS_ELF_SCAN_H
#define LITMUS_ELF_SCAN_H

#include <cstdint>
#include <string>
#include <vector>

namespace litmus {

// 一条 /proc/self/maps 记录（只留扫描需要的字段）。
struct MapRegion {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t offset = 0;
    uint64_t dev = 0;  // makedev(major, minor)，用来和磁盘文件的 st_dev 对齐
    uint64_t ino = 0;  // 用来确认「磁盘上这个路径还是被映射的那一个 inode」
    std::string perms;  // 原样保留（"r-xp"），样本里要用
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool deleted = false;  // 路径带 " (deleted)" 后缀
    std::string path;      // 原样保留，可能带 " (deleted)"
};

// inline hook 扫描结果（对应 JSON 的 inlineHook）
struct InlineScanResult {
    int libs = 0;       // 真正比对了符号的 .so 个数
    int scanned = 0;    // 实际比对了多少个函数入口
    int hits = 0;       // 内存字节 != 磁盘字节的函数入口数
    int tramp = 0;      // 其中命中「经典跳板」形态的个数（佐证，不作为唯一依据）
    int skipped = 0;    // 打开/解析失败的 .so 个数
    int truncated = 0;  // 1 = 撞到时间/数量上限，结果不完整
    long long ms = 0;
    std::vector<std::string> samples;  // 最多 8 条，每条 <= 120 字符
};

// GOT/PLT 落点检查结果（对应 JSON 的 gotCheck）
struct GotScanResult {
    int plt = 0;      // .rela.plt 里的条目总数
    int scanned = 0;  // 实际检查过的槽位数
    int bad = 0;      // 落点不在任何可执行段的槽位数
    int nulls = 0;    // 值为 0 的槽位数（弱符号未决议，不判定）
    long long ms = 0;
    std::vector<std::string> samples;
};

// 扫描 regions 里所有 file-backed .so 的函数入口，比对内存字节与磁盘字节。
// regions 必须是 /proc/self/maps 的全量解析结果（顺序不重要）。
// budgetMs 是硬预算（建议 28ms）；超时设 truncated=1 并返回已扫结果。
InlineScanResult scanInlineHooks(const std::vector<MapRegion> &regions, long long budgetMs);

// 检查本 so（liblitmusprobe.so）的 .rela.plt：每个 GOT 槽的落点必须落在某个可执行映射里。
// budgetMs 建议 8ms。
GotScanResult checkGotPlt(const std::vector<MapRegion> &regions, long long budgetMs);

}  // namespace litmus

#endif  // LITMUS_ELF_SCAN_H
