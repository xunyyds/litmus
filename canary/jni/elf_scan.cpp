// Litmus 检测内核 · 内存侧不变量扫描（与框架无关）
//
// 见 elf_scan.h 的设计说明。本文件不 include <elf.h>：Android 上要同时处理
// 32/64 位 ELF，而宿主编译期的 ElfW 只对应本进程 ABI，所以按 ELF 规范手写偏移。

#include "elf_scan.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>

namespace litmus {
namespace {

// ------------------------------------------------------------------ 硬上限
constexpr int kMaxLibs = 40;            // 最多扫 40 个 .so
constexpr int kMaxSymsPerLib = 200;     // 每个 .so 最多比对 200 个函数入口
constexpr uint64_t kCompareBytes = 16;  // 函数入口比对窗口
constexpr uint64_t kMaxElfBytes = 512ull * 1024 * 1024;
constexpr uint64_t kMaxDynsym = 200000;  // dynsym 条目数的合理性上限
constexpr int kMaxPltEntries = 512;
constexpr size_t kMaxSamples = 8;

// ------------------------------------------------------------------ ELF 常量
constexpr uint8_t kElfClass32 = 1;
constexpr uint8_t kElfClass64 = 2;

constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtDynamic = 2;
constexpr uint32_t kPfX = 1;

constexpr uint8_t kSttFunc = 2;

constexpr uint32_t kShtDynsym = 11;

constexpr uint64_t kDtNull = 0;
constexpr uint64_t kDtPltrelsz = 2;
constexpr uint64_t kDtHash = 4;
constexpr uint64_t kDtStrtab = 5;
constexpr uint64_t kDtSymtab = 6;
constexpr uint64_t kDtStrsz = 10;
constexpr uint64_t kDtSyment = 11;
constexpr uint64_t kDtPltrel = 20;
constexpr uint64_t kDtJmprel = 23;
constexpr uint64_t kDtGnuHash = 0x6ffffef5u;
constexpr uint64_t kDtRela = 7;

// ------------------------------------------------------------------ 小工具

long long nowMs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long long>(ts.tv_sec) * 1000LL + ts.tv_nsec / 1000000LL;
}

// Android 全是小端；这里直接按小端读，parse() 里校验 EI_DATA。
inline uint16_t rd16(const uint8_t *p) {
    uint16_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

inline uint32_t rd32(const uint8_t *p) {
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

inline uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

bool endsWith(const std::string &s, const char *suf) {
    const size_t n = strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

std::string stripDeleted(const std::string &p) {
    const char *kSuf = " (deleted)";
    if (endsWith(p, kSuf)) return p.substr(0, p.size() - strlen(kSuf));
    return p;
}

std::string baseNameOf(const std::string &p) {
    const size_t slash = p.rfind('/');
    return (slash == std::string::npos) ? p : p.substr(slash + 1);
}

uint64_t pageSize() {
    static const uint64_t ps = []() -> uint64_t {
        long v = sysconf(_SC_PAGESIZE);
        return (v > 0) ? static_cast<uint64_t>(v) : static_cast<uint64_t>(4096);
    }();
    return ps;
}

uint64_t alignDown(uint64_t v) {
    const uint64_t ps = pageSize();
    return v & ~(ps - 1);
}

bool contains(const MapRegion &r, uint64_t addr, uint64_t len) {
    if (addr < r.start || addr > r.end) return false;
    return len <= r.end - addr;
}

const MapRegion *findReadable(const std::vector<const MapRegion *> &regs, uint64_t addr,
                              uint64_t len) {
    for (const MapRegion *r : regs) {
        if (r->readable && contains(*r, addr, len)) return r;
    }
    return nullptr;
}

// ------------------------------------------------------------------ ELF 只读视图

struct PhdrView {
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t off = 0;
    uint64_t vaddr = 0;
    uint64_t filesz = 0;
    uint64_t memsz = 0;
};

class MappedElf {
  public:
    MappedElf() = default;
    ~MappedElf() { close(); }
    MappedElf(const MappedElf &) = delete;
    MappedElf &operator=(const MappedElf &) = delete;

    // 只读 mmap 磁盘文件；不写、不 mprotect。
    bool open(const std::string &path) {
        close();
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
            static_cast<uint64_t>(st.st_size) > kMaxElfBytes) {
            ::close(fd);
            return false;
        }
        const uint64_t sz = static_cast<uint64_t>(st.st_size);
        void *p = ::mmap(nullptr, static_cast<size_t>(sz), PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);  // mmap 之后 fd 可以立刻关掉，别占着
        if (p == MAP_FAILED) return false;
        base_ = static_cast<const uint8_t *>(p);
        size_ = sz;
        dev_ = (static_cast<uint64_t>(major(st.st_dev)) << 32) |
               static_cast<uint64_t>(minor(st.st_dev));
        ino_ = static_cast<uint64_t>(st.st_ino);
        return true;
    }

    void close() {
        if (base_ != nullptr) {
            ::munmap(const_cast<uint8_t *>(base_), static_cast<size_t>(size_));
            base_ = nullptr;
        }
        size_ = 0;
        cls_ = 0;
        dev_ = 0;
        ino_ = 0;
        loads_.clear();
        dyns_.clear();
    }

    // 解析 ELF 头 + program headers（PT_LOAD / PT_DYNAMIC）。
    bool parse() {
        if (base_ == nullptr || size_ < 64) return false;
        if (base_[0] != 0x7f || base_[1] != 'E' || base_[2] != 'L' || base_[3] != 'F') return false;
        cls_ = base_[4];
        if (cls_ != kElfClass32 && cls_ != kElfClass64) return false;
        if (base_[5] != 1) return false;  // 只支持 ELFDATA2LSB
        const bool is64 = (cls_ == kElfClass64);
        if (!is64 && size_ < 52) return false;

        etype_ = rd16(base_ + 16);
        machine_ = rd16(base_ + 18);
        const uint64_t phoff = is64 ? rd64(base_ + 32) : rd32(base_ + 28);
        const uint16_t phentsize = rd16(base_ + (is64 ? 54 : 42));
        const uint16_t phnum = rd16(base_ + (is64 ? 56 : 44));
        shoff_ = is64 ? rd64(base_ + 40) : rd32(base_ + 32);
        shentsize_ = rd16(base_ + (is64 ? 58 : 46));
        const uint16_t shnum = rd16(base_ + (is64 ? 60 : 48));
        shnum_ = (shnum == 0xffff) ? 0 : shnum;  // 扩展节数的库极少见，直接放弃

        const uint16_t minEnt = is64 ? 56 : 32;
        if (phnum == 0 || phnum > 512 || phentsize < minEnt) return false;
        if (phoff == 0 || phoff > size_) return false;
        if (static_cast<uint64_t>(phnum) * phentsize > size_ - phoff) return false;

        for (uint16_t i = 0; i < phnum; i++) {
            const uint8_t *p = base_ + phoff + static_cast<uint64_t>(i) * phentsize;
            PhdrView d;
            d.type = rd32(p);
            if (is64) {
                d.flags = rd32(p + 4);
                d.off = rd64(p + 8);
                d.vaddr = rd64(p + 16);
                d.filesz = rd64(p + 32);
                d.memsz = rd64(p + 40);
            } else {
                d.off = rd32(p + 4);
                d.vaddr = rd32(p + 8);
                d.filesz = rd32(p + 16);
                d.memsz = rd32(p + 20);
                d.flags = rd32(p + 24);
            }
            if (d.type == kPtLoad && d.off < size_) loads_.push_back(d);
            if (d.type == kPtDynamic) dyns_.push_back(d);
        }
        return !loads_.empty();
    }

    bool is64() const { return cls_ == kElfClass64; }
    uint16_t machine() const { return machine_; }
    uint16_t etype() const { return etype_; }
    const uint8_t *base() const { return base_; }
    uint64_t size() const { return size_; }
    uint64_t dev() const { return dev_; }
    uint64_t ino() const { return ino_; }
    const std::vector<PhdrView> &loads() const { return loads_; }
    const std::vector<PhdrView> &dyns() const { return dyns_; }

    // vaddr -> 文件内偏移（只覆盖 PT_LOAD 的 p_filesz 之内）。
    bool vaddrToOff(uint64_t vaddr, uint64_t &off) const {
        for (const PhdrView &s : loads_) {
            if (s.filesz == 0 || vaddr < s.vaddr) continue;
            const uint64_t delta = vaddr - s.vaddr;
            if (delta >= s.filesz) continue;
            const uint64_t o = s.off + delta;
            if (o >= size_) return false;
            off = o;
            return true;
        }
        return false;
    }

    // 返回包含 vaddr 的可执行 PT_LOAD；没有则 nullptr。
    const PhdrView *codeSegmentOf(uint64_t vaddr) const {
        for (const PhdrView &s : loads_) {
            if (s.filesz == 0 || vaddr < s.vaddr) continue;
            if (vaddr - s.vaddr >= s.filesz) continue;
            if ((s.flags & kPfX) != 0) return &s;
        }
        return nullptr;
    }

    // 取第 idx 个节头；DT_HASH/DT_GNU_HASH 都缺失时用来兜底数 dynsym。
    bool section(uint32_t idx, uint32_t &typeOut, uint64_t &offOut, uint64_t &sizeOut,
                 uint64_t &entsizeOut) const {
        if (shoff_ == 0 || shnum_ == 0 || idx >= shnum_) return false;
        const uint16_t minEnt = is64() ? 64 : 40;
        if (shentsize_ < minEnt) return false;
        const uint64_t o = shoff_ + static_cast<uint64_t>(idx) * shentsize_;
        if (o > size_ || shentsize_ > size_ - o) return false;
        const uint8_t *p = base_ + o;
        typeOut = rd32(p + 4);
        if (is64()) {
            offOut = rd64(p + 24);
            sizeOut = rd64(p + 32);
            entsizeOut = rd64(p + 56);
        } else {
            offOut = rd32(p + 16);
            sizeOut = rd32(p + 20);
            entsizeOut = rd32(p + 36);
        }
        return offOut < size_;
    }

  private:
    const uint8_t *base_ = nullptr;
    uint64_t size_ = 0;
    uint8_t cls_ = 0;
    uint16_t etype_ = 0;
    uint16_t machine_ = 0;
    uint64_t shoff_ = 0;
    uint16_t shentsize_ = 0;
    uint16_t shnum_ = 0;
    uint64_t dev_ = 0;
    uint64_t ino_ = 0;
    std::vector<PhdrView> loads_;
    std::vector<PhdrView> dyns_;
};

// ------------------------------------------------------------------ .dynamic

struct DynInfo {
    uint64_t symtab = 0;
    uint64_t strtab = 0;
    uint64_t strsz = 0;
    uint64_t syment = 0;
    uint64_t hash = 0;
    uint64_t gnuhash = 0;
    uint64_t jmprel = 0;
    uint64_t pltrelsz = 0;
    uint64_t pltrel = 0;
};

bool readDynamic(const MappedElf &f, DynInfo &di) {
    const uint64_t ent = f.is64() ? 16 : 8;
    for (const PhdrView &seg : f.dyns()) {
        if (seg.filesz == 0 || seg.off >= f.size()) continue;
        const uint64_t avail = std::min<uint64_t>(seg.filesz, f.size() - seg.off);
        const uint64_t n = std::min<uint64_t>(avail / ent, 4096);
        for (uint64_t i = 0; i < n; i++) {
            const uint8_t *p = f.base() + seg.off + i * ent;
            const uint64_t tag = f.is64() ? rd64(p) : rd32(p);
            const uint64_t val = f.is64() ? rd64(p + 8) : rd32(p + 4);
            if (tag == kDtNull) break;
            switch (tag) {
                case kDtSymtab: di.symtab = val; break;
                case kDtStrtab: di.strtab = val; break;
                case kDtStrsz: di.strsz = val; break;
                case kDtSyment: di.syment = val; break;
                case kDtHash: di.hash = val; break;
                case kDtGnuHash: di.gnuhash = val; break;
                case kDtJmprel: di.jmprel = val; break;
                case kDtPltrelsz: di.pltrelsz = val; break;
                case kDtPltrel: di.pltrel = val; break;
                default: break;
            }
        }
    }
    return di.symtab != 0;
}

// DT_GNU_HASH：nbuckets/symoffset/bloom_size/bloom_shift + bloom + buckets + chains
uint64_t gnuHashSymCount(const MappedElf &f, uint64_t hashVaddr) {
    uint64_t off = 0;
    if (!f.vaddrToOff(hashVaddr, off)) return 0;
    if (off + 16 > f.size()) return 0;
    const uint8_t *h = f.base() + off;
    const uint32_t nbuckets = rd32(h);
    const uint32_t symoffset = rd32(h + 4);
    const uint32_t bloomSize = rd32(h + 8);
    if (nbuckets == 0 || nbuckets > (1u << 20) || bloomSize > (1u << 20)) return 0;

    const uint64_t wordBytes = f.is64() ? 8 : 4;
    const uint64_t bucketsOff = off + 16 + static_cast<uint64_t>(bloomSize) * wordBytes;
    const uint64_t bucketsBytes = static_cast<uint64_t>(nbuckets) * 4;
    if (bucketsOff > f.size() || bucketsBytes > f.size() - bucketsOff) return 0;

    const uint8_t *buckets = f.base() + bucketsOff;
    uint32_t last = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        const uint32_t v = rd32(buckets + i * 4);
        if (v > last) last = v;
    }
    if (last < symoffset) return symoffset;
    const uint64_t chainBase = bucketsOff + bucketsBytes;
    uint64_t idx = last;
    for (uint64_t guard = 0; guard < kMaxDynsym; guard++, idx++) {
        if (idx < symoffset) return 0;
        const uint64_t pos = chainBase + (idx - symoffset) * 4;
        if (pos + 4 > f.size()) return 0;
        if ((rd32(f.base() + pos) & 1u) != 0) return idx + 1;
    }
    return 0;
}

// dynsym 条目数：DT_HASH → DT_GNU_HASH → 节头 SHT_DYNSYM → 距离估算。
uint64_t dynsymCount(const MappedElf &f, const DynInfo &di) {
    if (di.hash != 0) {
        uint64_t off = 0;
        if (f.vaddrToOff(di.hash, off) && off + 8 <= f.size()) {
            const uint32_t nchain = rd32(f.base() + off + 4);
            if (nchain > 0 && nchain <= kMaxDynsym) return nchain;
        }
    }
    if (di.gnuhash != 0) {
        const uint64_t n = gnuHashSymCount(f, di.gnuhash);
        if (n > 0 && n <= kMaxDynsym) return n;
    }
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t type = 0;
        uint64_t off = 0, size = 0, ent = 0;
        if (!f.section(i, type, off, size, ent)) continue;
        if (type == kShtDynsym && ent > 0) {
            const uint64_t n = size / ent;
            if (n > 0 && n <= kMaxDynsym) return n;
        }
    }
    uint64_t symOff = 0, strOff = 0;
    const uint64_t ent = di.syment ? di.syment : (f.is64() ? 24 : 16);
    if (ent >= 16 && f.vaddrToOff(di.symtab, symOff) && f.vaddrToOff(di.strtab, strOff) &&
        strOff > symOff) {
        const uint64_t n = (strOff - symOff) / ent;
        if (n > 0 && n <= kMaxDynsym) return n;
    }
    return 0;
}

// 读符号名（dynstr 里的 NUL 结尾串），失败返回空串。
std::string symNameAt(const MappedElf &f, uint64_t strtabOff, uint64_t strsz, uint32_t nameOff) {
    if (nameOff == 0) return std::string();
    const uint64_t pos = strtabOff + nameOff;
    if (pos >= f.size()) return std::string();
    uint64_t maxLen = 96;
    if (strsz > nameOff) maxLen = std::min<uint64_t>(maxLen, strsz - nameOff);
    if (maxLen > f.size() - pos) maxLen = f.size() - pos;
    if (maxLen == 0) return std::string();
    const char *s = reinterpret_cast<const char *>(f.base() + pos);
    size_t n = 0;
    while (n < maxLen && s[n] != '\0') n++;
    return std::string(s, n);
}

// ------------------------------------------------------------------ 跳板形态

// 只看入口头 16 字节。命中「经典跳板」只是佐证：字节不一致本身才是依据。
bool looksLikeTrampoline(const uint8_t *m) {
#if defined(__aarch64__) || defined(__arm__)
    const uint32_t i0 = rd32(m);
    const uint32_t i1 = rd32(m + 4);
    const uint32_t i2 = rd32(m + 8);
    // LDR X16, #8 ; BR X16   /   LDR X17, #8 ; BR X17
    if ((i0 == 0x58000050u && i1 == 0xD61F0200u) || (i0 == 0x58000051u && i1 == 0xD61F0220u))
        return true;
    // ADRP X16, ... ; ADD X16, X16, #.. ; BR X16
    if ((i0 & 0x9F00001Fu) == 0x90000010u && (i1 & 0xFFC003FFu) == 0x91000210u && i2 == 0xD61F0200u)
        return true;
    // ADRP X16, ... ; LDR X16, [X16, #..] ; BR X16
    if ((i0 & 0x9F00001Fu) == 0x90000010u && (i1 & 0xFFC003FFu) == 0xF9400210u && i2 == 0xD61F0200u)
        return true;
    // 首条就是 B <imm26>（veneer / thunk，也是常见 hook 形态）
    if ((i0 & 0xFC000000u) == 0x14000000u) return true;
    // 首条就是 BR Xn
    if ((i0 & 0xFFFFFC1Fu) == 0xD61F0000u) return true;
    return false;
#elif defined(__x86_64__) || defined(__i386__)
    if (m[0] == 0xE9) return true;                                   // jmp rel32
    if (m[0] == 0xFF && (m[1] == 0x25 || m[1] == 0xE0 || m[1] == 0xE6)) return true;  // jmp *[..]
    if (m[0] == 0xCC) return true;                                   // int3
    if (m[0] == 0x68 && m[5] == 0xC3) return true;                    // push imm32 ; ret
    if (m[0] == 0x48 && m[1] == 0xB8 && m[10] == 0xFF && m[11] == 0xE0)
        return true;  // movabs rax,imm ; jmp rax
    return false;
#else
    (void)m;
    return false;
#endif
}

// ------------------------------------------------------------------ inline hook 扫描

struct LibGroup {
    std::string path;  // 已去掉 " (deleted)"
    std::vector<const MapRegion *> regs;
    bool hasExec = false;
    bool deleted = false;
    uint64_t dev = 0;  // 来自 maps，用来确认磁盘文件就是被映射的那一个 inode
    uint64_t ino = 0;
    int score = 0;
};

int libScore(const std::string &path) {
    const std::string base = baseNameOf(path);
    int s = 0;
    if (base == "liblitmusprobe.so") s += 100;  // 自己的库最先扫
    if (path.compare(0, 10, "/data/app/") == 0) s += 60;
    else if (path.compare(0, 6, "/data/") == 0) s += 45;
    else if (path.find("/data/") != std::string::npos) s += 35;
    else if (path.compare(0, 8, "/system/") == 0 || path.compare(0, 6, "/apex/") == 0) s += 10;
    static const char *const kHot[] = {"libc.so",        "libm.so",
                                       "libdl.so",       "libart.so",
                                       "liblog.so",      "libandroid_runtime.so",
                                       "libnativehelper.so", "libc++_shared.so"};
    for (const char *h : kHot) {
        if (base == h) {
            s += 50;
            break;
        }
    }
    return s;
}

void pushSample(std::vector<std::string> &v, const std::string &s) {
    if (v.size() < kMaxSamples) v.push_back(s.size() > 120 ? s.substr(0, 120) : s);
}

// 比对单个 .so 的函数入口。真扫了（took>0）返回 true。
bool scanLib(const LibGroup &g, InlineScanResult &res, long long deadline) {
    MappedElf f;
    if (!f.open(g.path) || !f.parse()) {
        res.skipped++;
        return false;
    }
    // 磁盘上这个路径必须还是被 mmap 的那一个文件（包更新/overlay 会让磁盘版本变掉）
    if (g.ino != 0 && f.ino() != 0 && (g.ino != f.ino() || (g.dev != 0 && g.dev != f.dev()))) {
        res.skipped++;
        return false;
    }
    DynInfo di;
    if (!readDynamic(f, di)) {
        res.skipped++;
        return false;
    }
    const uint64_t nsyms = dynsymCount(f, di);
    uint64_t symOff = 0;
    if (nsyms < 2 || !f.vaddrToOff(di.symtab, symOff)) {
        res.skipped++;
        return false;
    }
    uint64_t strOff = 0;
    f.vaddrToOff(di.strtab, strOff);
    const uint64_t syment = di.syment ? di.syment : (f.is64() ? 24 : 16);
    if (syment < 16) {
        res.skipped++;
        return false;
    }

    const std::string baseName = baseNameOf(g.path);
    const uint64_t limit = std::min<uint64_t>(nsyms, kMaxDynsym);
    int took = 0;
    for (uint64_t i = 1; i < limit && took < kMaxSymsPerLib; i++) {
        if ((i & 15) == 0 && nowMs() > deadline) {
            res.truncated = 1;
            break;
        }
        const uint64_t entryOff = symOff + i * syment;
        if (entryOff > f.size() || syment > f.size() - entryOff) break;
        const uint8_t *e = f.base() + entryOff;
        const uint32_t stName = rd32(e);
        const uint8_t stInfo = f.is64() ? e[4] : e[12];
        if ((stInfo & 0x0fu) != kSttFunc) continue;  // 只要 STT_FUNC
        const uint64_t stValue = f.is64() ? rd64(e + 8) : rd32(e + 4);
        if (stValue == 0) continue;  // 未定义符号

        const PhdrView *seg = f.codeSegmentOf(stValue);
        if (seg == nullptr) continue;
        const uint64_t segDelta = stValue - seg->vaddr;
        if (kCompareBytes > seg->filesz || segDelta > seg->filesz - kCompareBytes) continue;
        const uint64_t fileOff = seg->off + segDelta;
        if (fileOff >= f.size() || kCompareBytes > f.size() - fileOff) continue;

        // 运行时地址 = load_bias + st_value；load_bias 由该段在 maps 里的 (offset,start) 反推
        const uint64_t segVaddrAligned = alignDown(seg->vaddr);
        const uint64_t segOffAligned = alignDown(seg->off);
        const uint8_t *fileBytes = f.base() + fileOff;
        bool compared = false;
        bool equal = false;
        bool haveDiff = false;
        bool tramp = false;
        int diffAt = 0;
        for (const MapRegion *r : g.regs) {
            if (r->offset != segOffAligned) continue;
            if (r->start < segVaddrAligned) continue;
            const uint64_t bias = r->start - segVaddrAligned;
            const uint64_t runtime = bias + stValue;
            if (findReadable(g.regs, runtime, kCompareBytes) == nullptr) continue;
            const uint8_t *mem = reinterpret_cast<const uint8_t *>(runtime);
            compared = true;
            if (memcmp(mem, fileBytes, static_cast<size_t>(kCompareBytes)) == 0) {
                equal = true;
                break;  // 同一 .so 被加载两份时，任一份一致就算干净
            }
            if (haveDiff) continue;
            haveDiff = true;
            for (uint64_t k = 0; k < kCompareBytes; k++) {
                if (mem[k] != fileBytes[k]) {
                    diffAt = static_cast<int>(k);
                    break;
                }
            }
            tramp = looksLikeTrampoline(mem);
        }
        if (!compared) continue;
        took++;
        res.scanned++;
        if (equal) continue;

        res.hits++;
        if (tramp) res.tramp++;
        const std::string name = symNameAt(f, strOff, di.strsz, stName);
        char tail[32];
        snprintf(tail, sizeof(tail), " +0x%x", diffAt);
        pushSample(res.samples, baseName + "!" + (name.empty() ? "?" : name) + tail);
    }
    if (took > 0) res.libs++;
    return took > 0;
}

// ------------------------------------------------------------------ GOT/PLT 落点

bool hasExecRegionCovering(const std::vector<MapRegion> &regions, uint64_t addr) {
    for (const MapRegion &r : regions) {
        if (!r.executable) continue;
        if (addr >= r.start && addr < r.end) return true;
    }
    return false;
}

// 取一个本 .so 内的代码地址，交给 dladdr 定位自身。
void selfAnchorNoop() {}

void *selfCodeAddress() {
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(&selfAnchorNoop));
}

}  // namespace

// ------------------------------------------------------------------ 对外入口

InlineScanResult scanInlineHooks(const std::vector<MapRegion> &regions, long long budgetMs) {
    const long long t0 = nowMs();
    const long long deadline = t0 + (budgetMs > 0 ? budgetMs : 1);
    InlineScanResult res;

    // 1) 按路径归并 maps 记录，只留 file-backed .so
    std::map<std::string, LibGroup> groups;
    for (const MapRegion &r : regions) {
        if (r.path.empty() || r.path[0] == '[') continue;
        const std::string clean = stripDeleted(r.path);
        if (!endsWith(clean, ".so")) continue;
        LibGroup &g = groups[clean];
        g.path = clean;
        g.regs.push_back(&r);
        if (r.executable) g.hasExec = true;
        if (r.deleted) g.deleted = true;
        if (g.ino == 0 && r.ino != 0) {
            g.ino = r.ino;
            g.dev = r.dev;
        }
    }

    // 2) 排序：自己的库 > 应用私有库 > 高频系统库 > 其它（同分按路径，保证可复现）
    std::vector<LibGroup *> order;
    order.reserve(groups.size());
    for (auto &kv : groups) {
        LibGroup &g = kv.second;
        if (!g.hasExec) continue;  // 没有可执行段就没有函数入口
        g.score = libScore(g.path);
        order.push_back(&g);
    }
    std::stable_sort(order.begin(), order.end(), [](const LibGroup *a, const LibGroup *b) {
        if (a->score != b->score) return a->score > b->score;
        return a->path < b->path;
    });

    // 3) 逐个扫，硬上限 40 个 .so
    const int total = static_cast<int>(order.size());
    const int libCap = std::min(total, kMaxLibs);
    for (int i = 0; i < libCap; i++) {
        if (nowMs() > deadline) {
            res.truncated = 1;
            break;
        }
        const LibGroup &g = *order[static_cast<size_t>(i)];
        if (g.deleted) {  // 磁盘文件未必还是被映射的那一份，比了没意义
            res.skipped++;
            continue;
        }
        scanLib(g, res, deadline);
    }
    if (total > libCap) res.truncated = 1;
    res.ms = nowMs() - t0;
    return res;
}

GotScanResult checkGotPlt(const std::vector<MapRegion> &regions, long long budgetMs) {
    const long long t0 = nowMs();
    const long long deadline = t0 + (budgetMs > 0 ? budgetMs : 1);
    GotScanResult res;

    // 1) 找到自己这个 so 的磁盘路径与 load bias
    std::string path;
    uint64_t bias = 0;
    bool haveBias = false;

    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(selfCodeAddress(), &info) != 0 && info.dli_fname != nullptr &&
        info.dli_fbase != nullptr) {
        path = info.dli_fname;
        bias = reinterpret_cast<uint64_t>(info.dli_fbase);
        haveBias = true;
    }
    if (path.empty()) {  // 兜底：按 basename 在 maps 里找
        for (const MapRegion &r : regions) {
            if (r.path.empty() || r.path[0] == '[') continue;
            if (baseNameOf(stripDeleted(r.path)) != "liblitmusprobe.so") continue;
            path = stripDeleted(r.path);
            break;
        }
    }
    MappedElf f;
    bool opened = !path.empty() && f.open(path) && f.parse();
    if (!opened) {  // dladdr 给的路径打不开：退回按 basename 在 maps 里找
        for (const MapRegion &r : regions) {
            if (r.path.empty() || r.path[0] == '[') continue;
            const std::string clean = stripDeleted(r.path);
            if (baseNameOf(clean) != "liblitmusprobe.so") continue;
            if (clean == path) continue;
            path = clean;
            haveBias = false;  // maps 路径的 bias 需要重新按段偏移推导
            opened = f.open(path) && f.parse();
            break;
        }
    }
    if (!opened) return res;
    DynInfo di;
    if (!readDynamic(f, di) || di.jmprel == 0 || di.pltrelsz == 0) return res;

    // 2) 本 so 在 maps 里的段，用于槽位可读性检查 / 兜底算 load bias
    const std::string selfBase = baseNameOf(path);
    std::vector<const MapRegion *> libRegs;
    for (const MapRegion &r : regions) {
        if (r.path.empty() || r.path[0] == '[') continue;
        const std::string clean = stripDeleted(r.path);
        if (baseNameOf(clean) != selfBase) continue;
        libRegs.push_back(&r);
    }
    if (!haveBias) {
        for (const PhdrView &seg : f.loads()) {
            const uint64_t segVaddrAligned = alignDown(seg.vaddr);
            const uint64_t segOffAligned = alignDown(seg.off);
            for (const MapRegion *r : libRegs) {
                if (r->offset != segOffAligned || r->start < segVaddrAligned) continue;
                bias = r->start - segVaddrAligned;
                haveBias = true;
                break;
            }
            if (haveBias) break;
        }
    }
    if (!haveBias) return res;

    // 3) 遍历 .rela.plt
    uint64_t jmpOff = 0;
    if (!f.vaddrToOff(di.jmprel, jmpOff)) return res;
    const bool isRela = (di.pltrel == kDtRela);
    const uint64_t entSize = isRela ? (f.is64() ? 24 : 12) : (f.is64() ? 16 : 8);
    const uint64_t avail = f.size() > jmpOff ? f.size() - jmpOff : 0;
    uint64_t count = std::min<uint64_t>(di.pltrelsz / entSize, avail / entSize);
    if (count > static_cast<uint64_t>(kMaxPltEntries)) count = kMaxPltEntries;
    res.plt = static_cast<int>(count);

    uint64_t strOff = 0;
    f.vaddrToOff(di.strtab, strOff);
    uint64_t symOff = 0;
    const bool haveSyms = f.vaddrToOff(di.symtab, symOff);
    const uint64_t symEnt = di.syment ? di.syment : (f.is64() ? 24 : 16);

    for (uint64_t i = 0; i < count; i++) {
        if ((i & 7) == 0 && nowMs() > deadline) break;
        const uint8_t *e = f.base() + jmpOff + i * entSize;
        const uint64_t rOffset = f.is64() ? rd64(e) : rd32(e);
        const uint64_t rInfo = f.is64() ? rd64(e + 8) : rd32(e + 4);
        const uint64_t slot = bias + rOffset;
        if (findReadable(libRegs, slot, 8) == nullptr) continue;
        uint64_t target = 0;
        memcpy(&target, reinterpret_cast<const void *>(slot), sizeof(target));
        res.scanned++;
        if (target == 0) {  // 弱符号未决议，不判定
            res.nulls++;
            continue;
        }
        if (hasExecRegionCovering(regions, target)) continue;
        res.bad++;
        std::string name;
        if (haveSyms && symEnt >= 16) {
            const uint64_t symIdx = f.is64() ? (rInfo >> 32) : (rInfo >> 8);
            const uint64_t so = symOff + symIdx * symEnt;
            if (so <= f.size() && symEnt <= f.size() - so) {
                name = symNameAt(f, strOff, di.strsz, rd32(f.base() + so));
            }
        }
        char buf[112];
        snprintf(buf, sizeof(buf), "%s!%s -> 0x%llx", selfBase.c_str(),
                 name.empty() ? "?" : name.c_str(),
                 static_cast<unsigned long long>(target & 0xffffffffffffull));
        pushSample(res.samples, buf);
    }
    res.ms = nowMs() - t0;
    return res;
}

}  // namespace litmus
