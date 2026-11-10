# Litmus 检测报告 · C1-litmus

> emulator-5554 / BVL-AN16 / SDK 32 / Android 12 ｜ profile `standard` ｜ 框架 `none` ｜ 2026-11-10T10:40:39Z ｜ 报告来源 `logcat:chunk(6)`

## ① 一句话结论

这个包没被改：哈希、打包指纹、签名都与构建产物一致，六类里没有一条被坐实。

有 5 条停在可疑，但它们都还够不上「被坐实」，多半是设备噪声，见 ⑦。

Litmus 分 94.0/100。这个分是「我们看着它有多干净」，越高说明越看不出来（100 = 一条篡改都没抓到，0 = 全被抓住）。

> 术语：干净（CLEAN）、可疑（SUSPECT）、被坐实（TAMPERED）、测不了（UNKNOWN）、探针出错（ERROR）、结果不稳定（FLAKY）。后三种不计分，也**不算干净**。tier 是证据强度：A 级=不变量/密码学，B 级=交叉视图，C 级=特征匹配（只能出可疑）。

## ② 三个数字

| Litmus 分 | 盲区类别 | 误报向量 |
| ---: | ---: | ---: |
| **94.0** | **0 类** | **0 条** |
| 越高说明我们越看不出来（100 = 一条篡改都没抓到） | 没有整类失明 | 没有需要豁免的红叉 |

## ③ 这次改了什么

三项都能对上：装上去的这份 APK 就是我们构建的那一份，没有被动过。

| 检查项 | 构建产物（期望） | 本次实测 | 结论 |
| --- | ---: | ---: | --- |
| APK 全文件哈希（sha256） | 56300ff196b1ffe1… | 56300ff196b1ffe1… | 一致 |
| 打包指纹（ZipEntry CRC/大小/压缩方式） | 68fa5c6bfb062aaa… | 68fa5c6bfb062aaa… | 一致 |
| 签名证书（sha256） | eb6414ca77181369… | eb6414ca77181369… | 一致 |

> 哈希/指纹/签名这三项里，只要有一项对不上，就说明装上去的这份包不是我们构建的那一份。签名只能证明「谁签的」，证明不了「内容没动」，所以两者都要看。

## ④ 逐类判断

### 运行时完整性（runtime-integrity）· 91.4 分

可判定 11 条里 9 条干净，2 条可疑，另有 1 条测不了（不计分）。最需要看的是 **rt.maps.exec_files**：可疑（SUSPECT），置信度 0.55。证据是 `exec mapping outside whitelist n=1 e0=/data/system/etc/mumu-configs/shared_libs…`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `rt.maps.exec_files` | B | 可疑（SUSPECT） | 0.55 | 3 | app | exec mapping outside whitelist n=1 e0=/data/system/etc/mumu… |
| `rt.thread.name` | C | 可疑（SUSPECT） | 0.35 | 3 | app | RenderThread x2 (dup renderer thread) |

### 注入痕迹（injection）· 90.5 分

可判定 6 条里 5 条干净，1 条可疑，另有 1 条测不了（不计分）。最需要看的是 **inj.module.paths**：可疑（SUSPECT），置信度 0.60。证据是 `libs=258 outside=[/data/system/etc/mumu-configs/shared_libs/libhp12_x86_64.so]`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `inj.module.paths` | C | 可疑（SUSPECT） | 0.60 | 4 | app | libs=258 outside=[/data/system/etc/mumu-configs/shared_libs… |

### 包完整性（package-integrity）· 100.0 分

可判定 9 条里 9 条干净，另有 2 条测不了（不计分）。这一类没有任何一条被判为可疑或被坐实。

### 提权面（privilege）· 87.0 分

可判定 7 条里 5 条干净，2 条可疑。最需要看的是 **priv.selinux**：可疑（SUSPECT），置信度 0.75。证据是 `selinux permissive (enforce=0) domain=u:r:untrusted_app:s0:c100,c256,c512,c768`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `priv.magisk` | C | 可疑（SUSPECT） | 0.55 | 3 | app | magisk trace=[path:debug_ramdisk] |
| `priv.selinux` | B | 可疑（SUSPECT） | 0.75 | 3 | app | selinux permissive (enforce=0) domain=u:r:untrusted_app:s0:… |

### 虚拟化/多开（virtualization）· 100.0 分

可判定 5 条里 5 条干净。这一类没有任何一条被判为可疑或被坐实。

### 环境面（environment）· 100.0 分

可判定 5 条里 5 条干净。这一类没有任何一条被判为可疑或被坐实。

## ⑤ 被坐实的问题

这次没有一条被坐实 —— 要么包确实没被改，要么改动只留下了「可疑」级别的痕迹（见 ④ 里的可疑项）。

## ⑥ 我们看不见的地方

这次包没被改，盲区判定不适用（盲区的前提是「包确实被改过」）。要检查盲区，请先跑一次带修补的对照运行。

## ⑦ 环境噪声

这次**没带基线**跑（`--baseline` 未给），所以无法区分「设备本来就脏」和「这次修补引入的问题」：下面的分数是绝对分，不是相对某台干净设备的增量。

另外要留意：5 条停在可疑（有痕迹但证据不足）；4 条完全测不了（这类不计分，但也不是「干净」）。

建议：在同一台设备上用 `--baseline` 再跑一次干净包，把这次的红叉逐条对照；同一份包重复跑如果分数抖动，抖动幅度本身就是噪声底（待实测）。

## ⑧ 怎么让分数上去

> 收益怎么算的：把某一类补到 100 分（或修掉一条红叉）后，按 profile 的类别权重折算成总分变化。**所有数字都是估算**，不含「改完之后检测能力是否真的变强」这层不确定性。

| 做什么 | 为什么 | 预计收益 | 成本 | 怎么做 |
| --- | --- | --- | --- | --- |
| 把 运行时完整性 的可疑项判成干净（或改成「测不了」） | 该类 2 条可疑把分数压在 91.4 分；可疑项要么补证据升级成结论，要么承认测不了。 | **预计 +2.1 分（估算）** | 中 | 逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。 |
| 把 注入痕迹 的可疑项判成干净（或改成「测不了」） | 该类 1 条可疑把分数压在 90.5 分；可疑项要么补证据升级成结论，要么承认测不了。 | **预计 +2.1 分（估算）** | 中 | 逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。 |
| 把 提权面 的可疑项判成干净（或改成「测不了」） | 该类 2 条可疑把分数压在 87.0 分；可疑项要么补证据升级成结论，要么承认测不了。 | **预计 +1.8 分（估算）** | 中 | 逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。 |

## ⑨ 附录

### 完整向量表（47 条，含干净项）

| id | 类别 | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| `rt.tracerpid` | runtime-integrity | A | 干净（CLEAN） | 0.95 | 4 | app | TracerPid=0 (status+native agree) |
| `rt.proc.pid` | runtime-integrity | B | 干净（CLEAN） | 0.90 | 2 | app | pid=6722 (java+stat agree) |
| `rt.got.integrity` | runtime-integrity | A | 干净（CLEAN） | 0.90 | 4 | app | GOT scanned=147 bad=0 |
| `rt.maps.file_integrity` | runtime-integrity | B | 测不了（UNKNOWN） | 0.00 | 4 | app | /proc/self/mem open denied (FileNotFoundException) |
| `rt.maps.deleted` | runtime-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | no file-backed (deleted) mapping |
| `rt.memfd` | runtime-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | memfd=0 (art-jit excluded=2) |
| `rt.maps.anon_exec` | runtime-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | anon-exec=0 bytes=0 |
| `rt.maps.exec_files` | runtime-integrity | B | 可疑（SUSPECT） | 0.55 | 3 | app | exec mapping outside whitelist n=1 e0=/data/system/etc/mumu-configs/shared_libs/libhp12_x86_64.so |
| `rt.vdso` | runtime-integrity | B | 干净（CLEAN） | 0.90 | 3 | app | vdso=4096B (both views agree) |
| `rt.timing` | runtime-integrity | B | 干净（CLEAN） | 0.85 | 2 | app | openat median=712ns p99=7424ns jitter=6712ns n=200 |
| `rt.thread.name` | runtime-integrity | C | 可疑（SUSPECT） | 0.35 | 3 | app | RenderThread x2 (dup renderer thread) |
| `rt.stack.frames` | runtime-integrity | C | 干净（CLEAN） | 0.95 | 2 | app | frames=6 no hook frame |
| `inj.elf.inline` | injection | B | 干净（CLEAN） | 0.80 | 4 | app | inline scan 4056 entries, 0 hit |
| `inj.proc.env` | injection | B | 测不了（UNKNOWN） | 0.00 | 3 | app | /proc/self/environ unreadable or empty |
| `inj.module.paths` | injection | C | 可疑（SUSPECT） | 0.60 | 4 | app | libs=258 outside=[/data/system/etc/mumu-configs/shared_libs/libhp12_x86_64.so] |
| `inj.module.marker` | injection | C | 干净（CLEAN） | 0.95 | 4 | app | libs=258 no engine marker in names |
| `inj.elf.rwx` | injection | C | 干净（CLEAN） | 0.95 | 3 | app | rwx=0 |
| `inj.frida.port` | injection | C | 干净（CLEAN） | 0.95 | 3 | app | tcp 27042/27043 closed |
| `inj.frida.socket` | injection | C | 干净（CLEAN） | 0.95 | 3 | app | no frida file/map/unix-socket trace (unix=readable) |
| `pkg.signature` | package-integrity | A | 干净（CLEAN） | 0.95 | 5 | app | cert=eb6414ca77181369… |
| `pkg.signing.v3` | package-integrity | A | 干净（CLEAN） | 0.95 | 5 | app | v3 signer=eb6414ca77181369… count=1 |
| `pkg.cert.history` | package-integrity | A | 干净（CLEAN） | 0.95 | 3 | app | history=1 matches baked set |
| `pkg.codepath.hash` | package-integrity | A | 测不了（UNKNOWN） | 0.00 | 5 | app | sha256=56300ff196b1ffe1… (CLI compares, codePath=base.apk) |
| `pkg.zip.fingerprint` | package-integrity | A | 测不了（UNKNOWN） | 0.00 | 5 | app | zipFp=68fa5c6bfb062aaa… (CLI compares) |
| `pkg.manifest` | package-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | appClass=io.litmus.canary.LitmusApp factory=android.app.AppComponentFactory |
| `pkg.dex` | package-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | dex=1 bytes=218928 magic ok |
| `pkg.installer` | package-integrity | C | 干净（CLEAN） | 0.95 | 2 | app | installer=null (adb/sideload baseline) |
| `pkg.proc.name` | package-integrity | B | 干净（CLEAN） | 0.95 | 3 | app | proc=io.litmus.canary pkg=io.litmus.canary |
| `priv.proc.uid` | privilege | A | 干净（CLEAN） | 0.95 | 5 | app | uid=10100 (app range, views agree) |
| `priv.su` | privilege | C | 干净（CLEAN） | 0.95 | 3 | app | no su binary in 13 common paths |
| `priv.magisk` | privilege | C | 可疑（SUSPECT） | 0.55 | 3 | app | magisk trace=[path:debug_ramdisk] |
| `priv.kernel` | privilege | C | 干净（CLEAN） | 0.95 | 3 | app | kernel version has no ksu/apatch marker |
| `priv.props` | privilege | C | 干净（CLEAN） | 0.95 | 3 | app | ro.debuggable=0 ro.secure=1 service.adb.root= |
| `priv.mounts` | privilege | B | 干净（CLEAN） | 0.95 | 3 | app | mounts=113 system/vendor all ro |
| `priv.selinux` | privilege | B | 可疑（SUSPECT） | 0.75 | 3 | app | selinux permissive (enforce=0) domain=u:r:untrusted_app:s0:c100,c256,c512,c768 |
| `virt.emulator.props` | virtualization | C | 干净（CLEAN） | 0.95 | 3 | app | no emulator marker in Build/props |
| `virt.emulator.files` | virtualization | C | 干净（CLEAN） | 0.95 | 3 | app | no emulator device node in 10 paths |
| `virt.emulator.hardware` | virtualization | C | 干净（CLEAN） | 0.95 | 2 | app | cores=4 sensors=14 |
| `virt.vapp` | virtualization | C | 干净（CLEAN） | 0.95 | 3 | app | codeDir/dataDir/libs match own package |
| `virt.multi.user` | virtualization | C | 干净（CLEAN） | 0.95 | 2 | app | userId=0 profiles=1 |
| `env.debuggable` | environment | A | 干净（CLEAN） | 0.95 | 3 | app | not debuggable (sdk=32) |
| `env.developer` | environment | C | 干净（CLEAN） | 0.95 | 2 | app | adb=0 dev=-1 wifiAdb=0 (usb adb is test baseline) |
| `env.proxy` | environment | C | 干净（CLEAN） | 0.95 | 2 | app | no proxy (global=) |
| `env.capture` | environment | C | 干净（CLEAN） | 0.95 | 2 | app | no accessibility service enabled |
| `env.overlay` | environment | C | 干净（CLEAN） | 0.95 | 2 | app | no overlay permission |
| `pkg.codepath.hash` | package-integrity | A | 干净（CLEAN） | 0.98 | 5 | cli | facts.apk.sha256=56300ff196b1ffe1… == expect.apkSha256，安装的 base.apk 与构建产物逐字节一致 |
| `pkg.zip.fingerprint` | package-integrity | A | 干净（CLEAN） | 0.98 | 5 | cli | facts.apk.zip.fingerprint=68fa5c6bfb062aaa… == expect.zipFingerprint，ZipEntry(CRC/size/method) 指纹一致 |

### 复现这条结果

```powershell
python cli\litmus.py score --report runs\C1-litmus-20261110-184039\report.raw.json --expect canary\out\build-info.json
# 输出到目录：
python cli\litmus.py score --report runs\C1-litmus-20261110-184039\report.raw.json --expect canary\out\build-info.json --save runs\C1-litmus-20261110-184039
```

- 本次运行：`C1-litmus`（none）· profile `standard` · CLI 0.1.0
- 报告来源：`logcat:chunk(6)` · App 侧运行 id `f4da99935b0144d8`
- 构建产物：`canary/out/litmus-canary-0.1.0.apk` · 0.1.0 · 构建于 2026-11-10T10:40:13Z
- 原始数据：`runs\C1-litmus-20261110-184039\run.json`（全量记账）与 `runs\C1-litmus-20261110-184039\report.raw.json`（App 原始报告）
- 向量覆盖率：目录声明 53 条，本次上报 45 条；未上报 8 条（`rt.art.entrypoint`、`rt.maps.cross_view`、`rt.signal.handlers`、`inj.loader.solist`、`inj.dex.inmemory`、`priv.caps`、`pkg.split`、`virt.vapp.binder`）
- 评分一致性：App 自算 94.0 分 vs CLI 重算 94.0 分（差 0.0）—— 一致

---

由 Litmus CLI 0.1.0 生成 · schema litmus.run/1 · 评分口径与 canary/io/litmus/core/Score.java 一致。
