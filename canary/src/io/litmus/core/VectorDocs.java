package io.litmus.core;

import java.util.HashMap;
import java.util.Map;

/**
 * 向量的人话文案（构建期由 tools/gen_vector_docs.py 从 schema/vectors.json 生成）。
 *
 * <p><b>不要手工编辑本文件</b>：改 schema/vectors.json 里对应条目的
 * {@code zh} / {@code plain} / {@code bypass}，然后重跑生成器。
 *
 * <p>App 详情卡与 CLI 报告读的是同一份文案，这是「说法一致」的工程保证。
 */
public final class VectorDocs {

    private static final Map<String, String[]> DOC = new HashMap<>();

    static {
        DOC.put("rt.tracerpid",
                new String[]{"`/proc/self/status` 的 `TracerPid` 必须为 0，且裸 `openat`+`read` 与 libc 两条路径读到的值一致——任何 ptrace 注入（frida-server / gdb / 调试器）必然让该字段非 0", "有别的东西在 ptrace 这个进程。正常的应用进程 TracerPid 恒为 0，非 0 只可能是调试器或注入器附着。", "要让它归零只能 detach 或改用非 ptrace 注入；后者通常会把痕迹转移到 rt.maps.anon_exec 和 inj.module.paths。"});
        DOC.put("rt.maps.anon_exec",
                new String[]{"匿名（无文件后端）且带 `x` 权限的映射字节数必须为 0——code cache 之外的 trampoline/补丁池只可能落在匿名可执行段", "进程里多出一块没有文件对应、却能执行的内存。正常应用只用它放 JIT 代码，其余多半是跳板池或解壳后的代码。", "把跳板搬进已映射 .so 的正文撞 rt.maps.file_integrity，塞进 memfd 撞 rt.memfd；三条路互斥，同时骗过成本高于不 hook。"});
        DOC.put("rt.maps.file_integrity",
                new String[]{"已映射 `.so` 的 `r-x` 段运行时字节必须逐字节等于磁盘同偏移字节——任何 inline hook / PLT 改写都会破坏该等式", "代码段被改过了。正常加载不会修改已映射 .so 的正文，只有 inline hook 会。", "跳板放匿名页会踩 rt.maps.anon_exec，改 GOT 会踩 rt.got.integrity——三条路互斥。"});
        DOC.put("rt.got.integrity",
                new String[]{"`.got`/`.data.rel.ro` 中每个已解析重定位槽的落点必须在「合法目标模块」的 `r-x` 区间内——GOT 劫持把槽值指向别处即破坏", "某个调用的目标被接走了。GOT 槽里存的地址不再指向原来的库，改它的人一般是为劫持系统调用。", "改回槽值就得放弃 PLT hook 转做 inline hook，那会撞 rt.maps.file_integrity；两条路只能选一条。"});
        DOC.put("rt.vdso",
                new String[]{"同一动作（`clock_gettime`/`gettimeofday`）经裸 `syscall` 与 libc 包装的返回值必须一致——只 hook libc 会在两条路径间露差", "libc 和内核给的答案对不上。同一次读时间，走 libc 与走裸 syscall 结果不同，说明 libc 那层被套了壳。", "只改 libc 会留这条；要连裸 syscall 一起骗，只能改探针自己 .so 里的 svc 指令——那条比对在 rt.maps.file_integrity 手上。"});
        DOC.put("rt.timing",
                new String[]{"固定 syscall（`openat(\"/dev/null\")`，必走真实陷入）的耗时中位数/p99 必须落在无插桩基线区间内——hook 分发必然引入额外分支与抖动", "系统调用比正常慢或抖得厉害。多中继一层就多几次分支，耗时分布整体右移；这条只当辅证，阈值待实测。", "压平抖动只能减少 hook 层数，等于关掉部分功能；改计时返回值会撞 rt.vdso 的双路径比对。"});
        DOC.put("rt.memfd",
                new String[]{"可执行映射不得来源于 `memfd:` 伪文件——用 memfd 装载可执行代码是「无文件进代码」的标准手法", "有代码是从内存文件（memfd）加载并执行的。这条路不落盘也不进 APK，正常应用没有理由用它。", "改成从磁盘临时文件加载会撞 rt.maps.exec_files 与 inj.module.paths；要躲开就得让代码留在合法 .so 里。"});
        DOC.put("rt.maps.deleted",
                new String[]{"映射中不得出现 `(deleted)` 的 file-backed **可执行**段——模块「加载完就卸载原文件」正是这个形态", "有些库的文件已经不在磁盘上，代码却还在跑。典型的加载完就删——文件藏起来了，映射本身抹不掉。", "不删文件就在 maps 里露出真实路径（撞 inj.module.paths），删了又留这条。两者只能选一个。"});
        DOC.put("rt.thread.name",
                new String[]{"线程名不得落在 hook 运行时保留名集合（`gum-js-loop`/`gmain`/`pool-frida`/`frida-*`）", "进程里有个线程取了 hook 工具的名字。这只是线索：装了 Frida 不等于这个进程被注入，单凭它只能判可疑。", "改线程名一行代码就够，且不牵动别的向量——这正是它只值权重 2 的原因；硬证据在 rt.maps.anon_exec。"});
        DOC.put("rt.stack.frames",
                new String[]{"从当前 Java 栈回溯必须取到预期的声明类与方法帧（Xposed/LSPlant 的影子帧会缺失或被替换）", "调用栈里少了本该有的帧，或多了一层不认识的中转。Java 层 hook 要藏真实调用者，栈最难同时伪造干净。", "伪造栈要拦截 Throwable 的填充，等于再挂一层 hook；新痕迹通常会落到 rt.maps.anon_exec 或线程名上。"});
        DOC.put("rt.art.entrypoint",
                new String[]{"已知 Java 方法的 ART 编译入口（`ArtMethod` 的 quick entry）必须落在 libart 自身的 `r-x` 映射内——Java 层 hook 必须改写该入口", "某个 Java 方法的执行入口不在 libart 里了。正常方法要么解释执行、要么编译进 libart，改入口是 Java hook 的第一步。", "只剩两条路：改入口（本条）或改 ART 编译产物（落进匿名可执行段，撞 rt.maps.anon_exec）。二者互斥。"});
        DOC.put("rt.maps.cross_view",
                new String[]{"同进程 maps 经 libc 读 `/proc/self/maps`、裸 `openat`、`/proc/thread-self/maps` 三条路径取到的内容必须逐行一致——hook 通常只覆盖其中一条", "同一张内存表，三种读法给出不同结果。能改一条路径的东西改不了三条，差异本身就是证据。", "三条读法要同时钩住，漏一条即命中；而钩这些读法本身要落代码在可执行内存里，正好被 rt.maps.anon_exec 看见。"});
        DOC.put("rt.signal.handlers",
                new String[]{"`SIGTRAP`/`SIGILL`/`SIGSEGV`/`SIGBUS` 的 handler 落点必须在 file-backed `r-x` 段内，且不等于 `SIG_DFL`/`SIG_IGN`", "致命信号的处理函数跑到了别处。反调试和部分引擎会接管 SIGTRAP/SIGSEGV，把处理函数指到自己的代码。", "要恢复得放弃信号驱动的断点机制；坚持保留的话处理函数只能落在匿名页，同时踩 rt.maps.anon_exec。"});
        DOC.put("rt.proc.pid",
                new String[]{"`Process.myPid()` 与 `/proc/self/stat` 里的 pid 必须一致；多个 pid 视图错位说明有进程伪装或 ptrace 侧通道", "两处报告的进程号不一致。正常进程的 pid 只有一份，对不上通常意味着有进程伪装或 ptrace 侧通道。", "让两处一致只能改 /proc 的读取结果，那等于 hook 内核视图；这么做会同时暴露在 rt.maps.cross_view 下。"});
        DOC.put("rt.maps.exec_files",
                new String[]{"maps 中可执行 file-backed 段只允许来自 `codePath`、`/system`、`/apex`、`/vendor`；出现 `/data/local/tmp` 等可写目录即可执行代码落盘", "可执行代码来自一个可写目录。系统目录和自己 APK 之外出现可执行映射，基本等于有人把 .so 拷出来跑了。", "放回 APK 或系统路径就得改包（撞 pkg.zip.fingerprint），留在可写目录则必中本条。没有第三条路。"});
        DOC.put("inj.frida.port",
                new String[]{"本机 27042/27043 不可连通（frida-server 控制端口默认落点）", "本机能连上 Frida 的默认控制端口。这只说明设备上跑着 frida-server，不代表这个包被注入了。", "frida-server 用 -l 换个端口就绕开；但换端口不改注入痕迹，ptrace 附着仍会被 rt.tracerpid 抓到。"});
        DOC.put("inj.frida.socket",
                new String[]{"`/proc/net/unix` 中不得出现 frida 系 socket 名（`frida`/`gum`/`linjector`）", "系统里有个 Frida 系的名字挂在 unix socket 上。同样是线索级证据：装了工具和真被注入是两件事。", "改 socket 名或改用 gadget 模式就不留这条；后者改成从包内加载 .so，痕迹转到 inj.module.paths。"});
        DOC.put("inj.elf.inline",
                new String[]{"函数入口前 N 条指令的**运行时字节**必须等于磁盘 ELF 同符号的指令字节——inline hook 必须先改这几字节", "函数的头几条指令被换掉了。这是 inline hook 的必经动作，跳板一定从入口开始改写。", "不改入口就得改调用方（撞 rt.got.integrity）或改 Java 入口（撞 rt.art.entrypoint）；三者是同一件事的三种下钩位置。"});
        DOC.put("inj.elf.rwx",
                new String[]{"不存在同时具 `w` 与 `x` 的映射——RWX 是未收敛 `mprotect` 的 hook 引擎典型残留", "有一块内存同时可写可执行。正常加载完成后不会留这种权限组合，多是引擎改完字节忘了收回写权限。", "补一次 mprotect 收回写权限就消失，且不牵动别的向量——它只值 C 的原因就在这；硬证据在 rt.maps.file_integrity。"});
        DOC.put("inj.proc.env",
                new String[]{"`/proc/self/environ` 不得含 `LD_PRELOAD`/`CLASSPATH`/`FRIDA_*` 等注入期变量", "进程的环境变量里有注入期留下的东西。LD_PRELOAD、FRIDA_ 这类变量只在启动那一刻被人塞进来。", "启动后清环境变量即可，成本极低；所以它只当辅证，主判据仍是 rt.maps.anon_exec。"});
        DOC.put("inj.module.paths",
                new String[]{"已加载 `.so` 路径全集必须 ⊂ 白名单（系统目录 + 自身 `codePath`/`nativeLibraryDir`/`splitSourceDirs`）", "加载了一个不该出现在这里的库。它既不在系统目录，也不在你 APK 的解压目录里。", "把库塞进 APK 的 lib 目录会改包（撞 pkg.zip.fingerprint），放 /data 下则必中本条。两条路互斥。"});
        DOC.put("inj.loader.solist",
                new String[]{"`dl_iterate_phdr()` 的模块集合必须等于 maps 中 file-backed 可执行段的模块集合——绕过 linker 手工映射的模块只会出现在一侧", "链接器名册和内存表对不上。有模块在跑而链接器不认识它——绕过 dlopen 手工映射的库只能这样藏着。", "要让链接器认识它就得给出真实路径（撞 inj.module.paths），不给就是本条。只能二选一。"});
        DOC.put("inj.dex.inmemory",
                new String[]{"运行时已加载 dex 集合必须 ⊆ 磁盘 `codePath`/`splitSourceDirs` 内的 dex 集合——`InMemoryDexClassLoader`/壳解密到内存会破坏包含关系", "有 dex 直接从内存加载，磁盘上找不到对应文件。热修复、加固壳和部分容器都这么做。", "让 dex 落盘就进了 APK 或 data 目录（撞 pkg.dex），不落盘就是本条。两者不可兼得。"});
        DOC.put("inj.module.marker",
                new String[]{"已加载模块/映射路径里出现注入框架标记目录名（`/data/adb/modules`、`/data/local/tmp/`、`riru`、`zygisk` 等）", "路径里出现了注入框架的目录名，比如模块目录或临时目录。名字是最容易改的东西，所以它只到可疑。", "换目录名或把模块装到别处即可，成本低；但模块仍要进进程，会留下 inj.loader.solist 的名册差。"});
        DOC.put("priv.su",
                new String[]{"常见 `su` 路径（`/system/xbin/su`、`/sbin/su`、`/system/bin/su`、`/data/local/tmp/su`）与可执行性不得同时成立", "设备上存在 su 可执行文件。不少国产 ROM 出厂就带，命中不等于这台机器真能提权。", "改名或挪走能绕开本条，但提权要动的东西仍会留痕——挂载记录撞 priv.mounts。"});
        DOC.put("priv.magisk",
                new String[]{"Magisk 目录/属性/包名（`/data/adb/magisk`、`persist.magisk.*`、`com.topjohnwu.magisk`）不得同时命中", "设备上有 Magisk 的目录、属性或管理器。装了面具不等于这个包被动过，但说明设备随时能被注入。", "Magisk 的隐藏能清掉目录与属性，但 Zygisk 注入留下的 (deleted) 映射清不掉——撞 rt.maps.deleted。"});
        DOC.put("priv.kernel",
                new String[]{"`/proc/version` 后缀与 `kallsyms` 符号中不得出现 KernelSU/APatch 的特征段", "内核版本或符号表里带着 root 方案的名字。这类方案在内核落脚，应用层几乎看不到别的痕迹。", "改 /proc/version 输出要动内核侧，成本高；反过来真给本进程提权时，priv.caps 会记下能力位。"});
        DOC.put("priv.props",
                new String[]{"`ro.debuggable`/`ro.secure`/`service.adb.root` 不得偏离出厂取值（用 `getprop` 三条路径交叉）", "几个系统属性和出厂状态不一样。调试开关、adb root 这类位被人改过时，通常顺手改了这一组。", "改回去需要 root，落手过程本身会在 priv.mounts 留痕；纯应用层改不到这些属性。"});
        DOC.put("priv.selinux",
                new String[]{"`getenforce` 必须为 `Enforcing`，且 `selinux` 挂载点存在", "设备的强制访问控制没在 enforcing。为跑注入把它关掉是省事做法，痕迹也一样明显。", "设回 enforcing 就消失，代价是注入手段要重新适配策略；当初放宽它的步骤多半已动过挂载（撞 priv.mounts）。"});
        DOC.put("priv.mounts",
                new String[]{"`/proc/self/mounts` 不得含 overlay/tmpfs/bind 挂到 `/system`、`/vendor`、`/data/adb` 的条目", "有目录被临时挂到系统分区上。模块化方案靠挂载把自己叠到系统路径，卸载后表里还可能留条目。", "umount 能把自见的挂载表清干净，但被加载过的模块映射还在（撞 rt.maps.deleted），下次挂载又会出现。"});
        DOC.put("priv.caps",
                new String[]{"`CapEff`/`CapPrm`/`CapBnd` 必须全 0，且 `Uid==Euid==Suid`、`Gid==Egid==Sgid`——提权面一旦真实存在，内核必然记录能力位", "这个进程拿到了不该有的内核能力位。普通应用的能力集是全零，出现任何一位都说明它不再是普通应用。", "要让能力位归零只能不借 su 启动；真借 su 跑起来的进程，会同时挂在 priv.su 上，两条一起亮。"});
        DOC.put("priv.proc.uid",
                new String[]{"`Process.myUid()` 必须落在普通应用 uid 区间且与 PMS 记录一致；容器/双开把 uid 换成宿主或隔离 uid 时该等式不成立", "进程的用户号和包管理记录对不上。容器与双开会把身份换成宿主或隔离用户，于是一个进程有了两个身份。", "要一致就得真跑在自己 uid 下，也就是不用容器；容器侧硬改会同时踩 virt.vapp.binder 的 Binder 归属校验。"});
        DOC.put("pkg.signature",
                new String[]{"`GET_SIGNATURES` 全量证书集合的 SHA-256 必须等于 build-info 烘入的期望证书", "签名证书和编译时记录的不一样。重打包、换 key、二次签名都会走到这一步，这是最硬的一条。", "过签能把本条归一化回绿，但文件哈希那两条在进程外算、改不到——见 pkg.codepath.hash。"});
        DOC.put("pkg.signing.v3",
                new String[]{"`getApkContentsSigners()` 全数组 + `hasMultipleSigners` 必须与期望一致（与 `pkg.signature` **两套期望**，契约见 `review/83-金丝雀验收.md` §4.1）", "新签名接口给出的证书集不对了。它和旧接口是两套期望值，只改一边会在这里露出来。", "过签要同时改 signatures 与 signingInfo，只改一边就被本条抓住；改齐了还有 pkg.codepath.hash 兜着。"});
        DOC.put("pkg.cert.history",
                new String[]{"`getSigningCertificateHistory()` 的证书集合与次序必须等于期望轮换链", "证书轮换历史和记录的不一致。轮换包里新旧两张本来就不同，改错一张就会露馅。", "伪造历史要连 lineage 一起造，工作量与重签一个包相当；它和 pkg.signature 是同一份证据的两面。"});
        DOC.put("pkg.codepath.hash",
                new String[]{"`codePath` 指向文件的 SHA-256 必须等于期望 `apkSha256`（**CLI 判**，App 侧改不到）", "磁盘上的 APK 和构建时算出的哈希不一样。这条在应用外面算，包内怎么 hook 都改不到它。", "要让它绿只能做 openat 级重定向，那层 hook 落在可执行内存（撞 rt.maps.anon_exec），与 pkg.zip.fingerprint 同源。"});
        DOC.put("pkg.zip.fingerprint",
                new String[]{"central directory 的 ZipEntry 指纹（契约 §4.4）必须等于期望值", "包内文件清单的指纹变了。多一个文件、少一个、改一个字节，都会让这串指纹不同。", "保持指纹不变就不能往包里加东西，注入只能全放内存——那会撞 rt.maps.anon_exec 与 inj.dex.inmemory。"});
        DOC.put("pkg.installer",
                new String[]{"`installerPackageName` 必须落在期望集合内（侧载/商店/adb 三态）", "包不是从应用商店装的。侧载很常见，所以这条只到「可疑」，单凭它不能定案。", "改 PackageManager 返回值即可，但改了会踩 pkg.manifest 的 Application 类校验——低权重项不值得为此动手。"});
        DOC.put("pkg.manifest",
                new String[]{"`appComponentFactory`/`appClass` 必须等于 build-info 期望值，且 `ApplicationInfo` 与 `ActivityThread.mApplicationInfo` 两处读数一致", "清单里的入口类被换过了。appComponentFactory 或 Application 类一旦不是原值，多半是为在启动最早插一脚。", "改回原值就失去入口 hook，注入只能等进程起来——痕迹会转给 rt.maps.anon_exec 与 inj.loader.solist。"});
        DOC.put("pkg.dex",
                new String[]{"APK 内 `classes*.dex` 的数量与 CRC 指纹必须等于期望值（CLI 复核）", "包里 dex 的数量和指纹变了。加壳、插补丁 dex、删调试代码都会改变它。", "不动 dex 就只能把代码放 native 或内存（撞 inj.dex.inmemory）；dex 一改，pkg.zip.fingerprint 也跟着变。"});
        DOC.put("pkg.split",
                new String[]{"`splitNames[]`、`splitSourceDirs[]` 与磁盘实际 `split_config.*.apk` 必须一一对应（数量/名字/次序）", "分包的名单和磁盘上实际存在的分片对不上。重打包工具常在这里丢分片，或把分片塞回主包。", "补齐分片要重签整个包（撞 pkg.signature），不补则本条命中。没有第三条路。"});
        DOC.put("pkg.proc.name",
                new String[]{"`Application.getProcessName()` 必须是包名本身或以 `<包名>:` 开头的子进程；出现宿主包名说明被容器代跑", "进程名不是这个包自己的。容器会用自己的进程名跑别人的代码，此时包名与进程名对不上。", "改进程名要 hook AMS 层返回值，而 virt.vapp.binder 会从 Binder 侧再看一次同一件事。"});
        DOC.put("virt.emulator.props",
                new String[]{"`ro.kernel.qemu`/`ro.hardware`(goldfish/ranchu)/`ro.boot.qemu` 不得命中", "系统属性里带着模拟器标记。这是最容易改的一层，改完还得看文件与硬件两面的读数。", "改属性是模拟器去特征的常规手段，能绕开本条；但漏改就轮到 virt.emulator.files 或硬件那条命中。"});
        DOC.put("virt.emulator.files",
                new String[]{"`/dev/qemu_pipe`、`/dev/goldfish_pipe`、`/sys/qemu_trace` 不得同时存在", "设备上有模拟器专用的管道文件。真机不会创建这些设备节点，它们是宿主与客户机通信的通道。", "删文件或换路径可行，但属性与硬件特征仍在（撞 virt.emulator.props）；三面要一起编。"});
        DOC.put("virt.emulator.hardware",
                new String[]{"CPU 核数/传感器集合/GPU renderer 三者不得同时落在「模拟器典型值」区间", "核数、传感器和显卡凑成了模拟器的典型组合。真机上这三样几乎不会同时这么整齐。", "伪造传感器是系统级改动，比改属性难得多；只改一两样，剩下的会落在 virt.emulator.props 或 files 那条。"});
        DOC.put("virt.vapp",
                new String[]{"maps/路径中不得出现 VirtualApp 系宿主包特征（宿主 `codePath`、`/data/data/<host>/virtual/`）", "路径里出现了容器宿主的包。多开方案把客应用塞在宿主数据目录里跑，路径会替它说话。", "换宿主包名或换容器实现能绕开本条，但进程名与 uid 归属仍会错位——见 virt.vapp.binder。"});
        DOC.put("virt.multi.user",
                new String[]{"用户/工作资料数与 `userId` 偏移必须等于默认单用户形态", "设备上有多用户或工作资料。这本身是系统功能，只是它和双开共用同一套身份机制，容易误伤。", "不需要绕，关掉工作资料即可；它和 priv.mounts 一样看设备形态而非包，所以必须靠基线判读。"});
        DOC.put("virt.vapp.binder",
                new String[]{"`Process.myUid()` 必须等于 PMS 记录的自身 uid，且自调用 Binder 路径的 `getCallingUid()` 与之一致——容器代客调用必然让 uid 归属错位", "进程身份和包管理记录对不上。容器代客调用系统服务时 uid 归属必然错位，这是容器最难藏的一处。", "要让 uid 对齐就得真跑在自己进程里，也就是不用容器；单改一边读数会踩 priv.proc.uid 的同一处校验。"});
        DOC.put("env.debuggable",
                new String[]{"`ApplicationInfo.FLAG_DEBUGGABLE` 必须为 0——这是清单里的位，改了就是改了", "这个包被标成了可调试。重打包时常为看日志顺手打开它，但它写死在清单里，改了就是改了。", "关掉它要重签整个包，签名与指纹两条跟着一起红（撞 pkg.signature）；留着就只能等别的向量先绿。"});
        DOC.put("env.developer",
                new String[]{"开发者选项与 `adb_enabled` 必须为关（`Settings.Global` 三条键交叉）", "开发者选项或 USB 调试开着。这是使用姿势而非包的问题，通常只用来解释分数。", "关掉开关就没了，不需要技术手段；留着时调试器真接上去，会先在 rt.tracerpid 留下非 0。"});
        DOC.put("env.proxy",
                new String[]{"全局 HTTP 代理与 VPN `TRANSPORT_VPN` 不得同时成立", "设备上挂着代理或 VPN。抓包与公司网络都会命中，它解释的是流量为什么不走直连。", "关代理即可，不必改包；改成 hook 读取反而要在可执行内存里落代码，撞 rt.maps.anon_exec。"});
        DOC.put("env.capture",
                new String[]{"已启用的无障碍服务/投屏录屏不得包含非期望项", "有别的程序在看这一屏。无障碍、投屏、录屏都会命中，正常辅助工具同样会触发。", "关掉对应服务即可；这条与包内改动无关，换成 hook 读取只会平白撞上 rt.maps.anon_exec。"});
        DOC.put("env.overlay",
                new String[]{"`TYPE_APPLICATION_OVERLAY` 悬浮窗授权不得对本应用生效", "有悬浮窗权限挂着。游戏加速器、录屏按钮都会申请，单看它说明不了什么。", "关权限即可，不涉及包内改动；它只把环境有异物记一笔，判读价值低于 pkg.signature 这类硬证据。"});
    }

    private VectorDocs() {
    }

    private static String get(String id, int idx) {
        if (id == null) {
            return "";
        }
        String[] v = DOC.get(id);
        return (v == null || idx >= v.length || v[idx] == null) ? "" : v[idx];
    }

    /** 一句话判据。 */
    public static String zh(String id) {
        return get(id, 0);
    }

    /** 人话解释：这条红了意味着什么（没有时回落判据）。 */
    public static String plain(String id) {
        String s = get(id, 1);
        return s.isEmpty() ? zh(id) : s;
    }

    /** 怎么绕过 / 绕过会踩到哪条别的向量。 */
    public static String bypass(String id) {
        String s = get(id, 2);
        return s.isEmpty()
                ? "暂无已整理的绕过路径；按「不变量」思路，要让它变绿必须同时让相关等式重新成立。"
                : s;
    }

    public static int size() {
        return DOC.size();
    }
}
