# Litmus 检测报告 · C2-repack

> BVL-AN16 / SDK 32 / Android 12 ｜ profile `standard` ｜ 框架 `-` ｜ 2026-11-10T09:12:33Z ｜ 报告来源 `offline:runs\C2-repack-20261110-164602\report.raw.json`

## ① 一句话结论

这个包**被改过**（内容哈希、打包指纹和签名都与构建产物对不上），其中「包完整性」掉得最狠（36.1 分，5 条被坐实）。

但「虚拟化/多开和环境面」一条都没抓到 —— 这几类对本次修补是失明的，见 ⑥。

Litmus 分 82.3/100。这个分是「我们看着它有多干净」，越高说明越看不出来（100 = 一条篡改都没抓到，0 = 全被抓住）。

> 术语：干净（CLEAN）、可疑（SUSPECT）、被坐实（TAMPERED）、测不了（UNKNOWN）、探针出错（ERROR）、结果不稳定（FLAKY）。后三种不计分，也**不算干净**。tier 是证据强度：A 级=不变量/密码学，B 级=交叉视图，C 级=特征匹配（只能出可疑）。

## ② 三个数字

| Litmus 分 | 盲区类别 | 误报向量 |
| ---: | ---: | ---: |
| **82.3** | **2 类** | **0 条** |
| 越高说明我们越看不出来（100 = 一条篡改都没抓到） | 包被改过却整类满分的类别，见 ⑥ | 没有需要豁免的红叉 |

## ③ 这次改了什么

签名变了，内容和打包指纹也跟着变 —— 整包被**重新签名并重打包**，这是最常见的「换个证书再装一遍」。

| 检查项 | 构建产物（期望） | 本次实测 | 结论 |
| --- | ---: | ---: | --- |
| APK 全文件哈希（sha256） | d67c1b0aa5a43195… | 56b1ff12136895b2… | **不一致** |
| 打包指纹（ZipEntry CRC/大小/压缩方式） | 0b47e92e325b5e47… | e719cec777d3f8af… | **不一致** |
| 签名证书（sha256） | 54f81573a7dfb033… | ceb1325f578f932a… | **不一致** |

> 哈希/指纹/签名这三项里，只要有一项对不上，就说明装上去的这份包不是我们构建的那一份。签名只能证明「谁签的」，证明不了「内容没动」，所以两者都要看。

## ④ 逐类判断

### 运行时完整性（runtime-integrity）· 95.7 分

可判定 11 条里 10 条干净，1 条可疑，另有 1 条测不了（不计分）。最需要看的是 **rt.maps.exec_files**：可疑（SUSPECT），置信度 0.55。证据是 `exec mapping outside whitelist n=1 e0=/data/system/etc/mumu-configs/shared_libs…`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `rt.maps.exec_files` | B | 可疑（SUSPECT） | 0.55 | 3 | app | exec mapping outside whitelist n=1 e0=/data/system/etc/mumu… |

### 注入痕迹（injection）· 90.5 分

可判定 6 条里 5 条干净，1 条可疑，另有 1 条测不了（不计分）。最需要看的是 **inj.module.paths**：可疑（SUSPECT），置信度 0.60。证据是 `libs=248 outside=[/data/system/etc/mumu-configs/shared_libs/libhp12_x86_64.so]`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `inj.module.paths` | C | 可疑（SUSPECT） | 0.60 | 4 | app | libs=248 outside=[/data/system/etc/mumu-configs/shared_libs… |

### 包完整性（package-integrity）· 36.1 分

可判定 9 条里 4 条干净，5 条被坐实，另有 2 条测不了（不计分）。最需要看的是 **pkg.signature**：被坐实（TAMPERED），置信度 1.00。证据是 `expect=54f81573a7dfb033… actual=[ceb1325f578f932a…]`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `pkg.signature` | A | 被坐实（TAMPERED） | 1.00 | 5 | app | expect=54f81573a7dfb033… actual=[ceb1325f578f932a…] |
| `pkg.signing.v3` | A | 被坐实（TAMPERED） | 1.00 | 5 | app | expect=54f81573a7dfb033… actual=[ceb1325f578f932a…] |
| `pkg.cert.history` | A | 被坐实（TAMPERED） | 0.95 | 3 | app | expect=[54f81573a7dfb033…] actual=[ceb1325f578f932a…] (n=1/… |
| `pkg.codepath.hash` | A | 被坐实（TAMPERED） | 1.00 | 5 | cli | facts.apk.sha256=56b1ff12136895b2… ≠ expect.apkSha256=d67c1… |
| `pkg.zip.fingerprint` | A | 被坐实（TAMPERED） | 1.00 | 5 | cli | facts.apk.zip.fingerprint=e719cec777d3f8af… ≠ expect.zipFin… |

### 提权面（privilege）· 87.0 分

可判定 7 条里 5 条干净，2 条可疑。最需要看的是 **priv.selinux**：可疑（SUSPECT），置信度 0.75。证据是 `selinux permissive (enforce=0) domain=u:r:untrusted_app:s0:c85,c256,c512,c768`。

| id | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `priv.magisk` | C | 可疑（SUSPECT） | 0.55 | 3 | app | magisk trace=[path:debug_ramdisk] |
| `priv.selinux` | B | 可疑（SUSPECT） | 0.75 | 3 | app | selinux permissive (enforce=0) domain=u:r:untrusted_app:s0:… |

### 虚拟化/多开（virtualization）· 100.0 分

可判定 5 条里 5 条干净。这一类没有任何一条被判为可疑或被坐实。**注意**：包确实被改过，这一类却拿了满分 —— 也就是说它对着这次修补完全瞎了，见 ⑥。

### 环境面（environment）· 100.0 分

可判定 5 条里 5 条干净。这一类没有任何一条被判为可疑或被坐实。**注意**：包确实被改过，这一类却拿了满分 —— 也就是说它对着这次修补完全瞎了，见 ⑥。

## ⑤ 被坐实的问题

5 条向量拿到了 A/B 级证据，直接判定为被改。每条都按「判据 / 证据 / 意味着什么 / 怎么修」写清楚。

#### pkg.signature · package-integrity · A 级

- **判据**：`GET_SIGNATURES` 全量证书集合的 SHA-256 必须等于 build-info 烘入的期望证书
- **证据**：`expect=54f81573a7dfb033… actual=[ceb1325f578f932a…]`
- **意味着什么**：签名证书和编译时记录的不一样。重打包、换 key、二次签名都会走到这一步，这是最硬的一条。 A 级结论本身就是不变量，出现就意味着改动一定发生过。
- **怎么修**：对手的绕过路径是「过签能把本条归一化回绿，但文件哈希那两条在进程外算、改不到——见 pkg.codepath.hash」；加固方向就是堵死这条路。

#### pkg.signing.v3 · package-integrity · A 级

- **判据**：`getApkContentsSigners()` 全数组 + `hasMultipleSigners` 必须与期望一致（与 `pkg.signature` **两套期望**，契约见 `review/83-金丝雀验收.md` §4.1）
- **证据**：`expect=54f81573a7dfb033… actual=[ceb1325f578f932a…]`
- **意味着什么**：新签名接口给出的证书集不对了。它和旧接口是两套期望值，只改一边会在这里露出来。 A 级结论本身就是不变量，出现就意味着改动一定发生过。
- **怎么修**：对手的绕过路径是「过签要同时改 signatures 与 signingInfo，只改一边就被本条抓住；改齐了还有 pkg.codepath.hash 兜着」；加固方向就是堵死这条路。

#### pkg.cert.history · package-integrity · A 级

- **判据**：`getSigningCertificateHistory()` 的证书集合与次序必须等于期望轮换链
- **证据**：`expect=[54f81573a7dfb033…] actual=[ceb1325f578f932a…] (n=1/1)`
- **意味着什么**：证书轮换历史和记录的不一致。轮换包里新旧两张本来就不同，改错一张就会露馅。 A 级结论本身就是不变量，出现就意味着改动一定发生过。
- **怎么修**：对手的绕过路径是「伪造历史要连 lineage 一起造，工作量与重签一个包相当；它和 pkg.signature 是同一份证据的两面」；加固方向就是堵死这条路。

#### pkg.codepath.hash · package-integrity · A 级

- **判据**：`codePath` 指向文件的 SHA-256 必须等于期望 `apkSha256`（**CLI 判**，App 侧改不到）
- **证据**：`facts.apk.sha256=56b1ff12136895b2… ≠ expect.apkSha256=d67c1b0aa5a43195…，装上去的 APK 不是构建产出的那个`
- **意味着什么**：磁盘上的 APK 和构建时算出的哈希不一样。这条在应用外面算，包内怎么 hook 都改不到它。 A 级结论本身就是不变量，出现就意味着改动一定发生过。
- **怎么修**：对手的绕过路径是「要让它绿只能做 openat 级重定向，那层 hook 落在可执行内存（撞 rt.maps.anon_exec），与 pkg.zip.fingerprint 同源」；加固方向就是堵死这条路。

#### pkg.zip.fingerprint · package-integrity · A 级

- **判据**：central directory 的 ZipEntry 指纹（契约 §4.4）必须等于期望值
- **证据**：`facts.apk.zip.fingerprint=e719cec777d3f8af… ≠ expect.zipFingerprint=0b47e92e325b5e47…，ZipEntry 指纹变了 → 包被重打包/改过内容`
- **意味着什么**：包内文件清单的指纹变了。多一个文件、少一个、改一个字节，都会让这串指纹不同。 A 级结论本身就是不变量，出现就意味着改动一定发生过。
- **怎么修**：对手的绕过路径是「保持指纹不变就不能往包里加东西，注入只能全放内存——那会撞 rt.maps.anon_exec 与 inj.dex.inmemory」；加固方向就是堵死这条路。

## ⑥ 我们看不见的地方

盲区（blind spot）= 包**确实被改过**，但整类检测一条都没抓到。这是我们要补的洞，不是用户的错。下面每一类都给出「为什么可能是洞」和「怎么验证是不是洞」。

#### ⚠ 虚拟化/多开（virtualization）· 100.0 分 · 5 条向量全干净

**虚拟化/多开（virtualization）** 5 条向量全部是「干净」的，可这个包**确实被改过**：也就是说整类检测对这次修补一条都没抓到。

为什么可能是洞：这一类的构成是 5 条 C 级，一条 A/B 级的不变量都没有。C 级是「特征匹配」（包名/属性/文件/端口/线程名），它只认**见过的痕迹**；这次修补恰好没留下它们，但下一次的修补只要多花一步就能绕开 —— 整类没有不变量，等于这一类只能靠对手犯错。

怎么验证是不是洞：1）换一台真机（非模拟器、非多开）跑同一个包：该类仍然满分 → 说明它检测的是「环境像不像模拟器」，与「包被改」本来就无关，不算洞；2）造一份「真的动了这一面」的样板包（改 ro 属性 / 塞进 VirtualApp），如果它还是满分 → 真洞；3）补一条硬件面不变量（传感器清单 / GPU 指纹）再跑，若新向量也是干净，基本可以确诊。

#### ⚠ 环境面（environment）· 100.0 分 · 5 条向量全干净

**环境面（environment）** 5 条向量全部是「干净」的，可这个包**确实被改过**：也就是说整类检测对这次修补一条都没抓到。

为什么可能是洞：这一类的构成是 1 条 A 级，4 条 C 级。里面确实有更强的证据级别，但它们对这次修补没反应 —— 要么探针没覆盖到真正的改动点，要么这些不变量的观测面选错了。

怎么验证是不是洞：1）把同一个包在原设备上跑两次，看这一类是否波动 → 会波动说明测的是环境噪声，不是篡改；2）手工把设备「弄脏」（打开开发者选项、挂代理），该类应掉分；不掉分 → 真洞；3）检查这些向量的 tier：如果全是 C 级特征匹配，它们本来就抓不到「包被改」这件事。

## ⑦ 环境噪声

这次**没带基线**跑（`--baseline` 未给），所以无法区分「设备本来就脏」和「这次修补引入的问题」：下面的分数是绝对分，不是相对某台干净设备的增量。

另外要留意：4 条停在可疑（有痕迹但证据不足）；4 条完全测不了（这类不计分，但也不是「干净」）；2 类整体失明（见 ⑥）。

建议：在同一台设备上用 `--baseline` 再跑一次干净包，把这次的红叉逐条对照；同一份包重复跑如果分数抖动，抖动幅度本身就是噪声底（待实测）。

## ⑧ 怎么让分数上去

> 收益怎么算的：把某一类补到 100 分（或修掉一条红叉）后，按 profile 的类别权重折算成总分变化。**所有数字都是估算**，不含「改完之后检测能力是否真的变强」这层不确定性。

| 做什么 | 为什么 | 预计收益 | 成本 | 怎么做 |
| --- | --- | --- | --- | --- |
| 处理 pkg.signature（包完整性） | 它是可判定项里权重 5 的红叉，「包完整性」的分数主要被它拉着。 | **预计 +2.8 分（估算）** | 小 | 对手的绕过路径是「过签能把本条归一化回绿，但文件哈希那两条在进程外算、改不到——见 pkg.codepath.hash」；加固方向就是堵死这条路。 |
| 处理 pkg.signing.v3（包完整性） | 它是可判定项里权重 5 的红叉，「包完整性」的分数主要被它拉着。 | **预计 +2.8 分（估算）** | 小 | 对手的绕过路径是「过签要同时改 signatures 与 signingInfo，只改一边就被本条抓住；改齐了还有 pkg.codepath.hash 兜着」；加固方向就是堵死这条路。 |
| 把 注入痕迹 的可疑项判成干净（或改成「测不了」） | 该类 1 条可疑把分数压在 90.5 分；可疑项要么补证据升级成结论，要么承认测不了。 | **预计 +2.1 分（估算）** | 中 | 逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。 |
| 把 提权面 的可疑项判成干净（或改成「测不了」） | 该类 2 条可疑把分数压在 87.0 分；可疑项要么补证据升级成结论，要么承认测不了。 | **预计 +1.8 分（估算）** | 中 | 逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。 |
| 把 运行时完整性 的可疑项判成干净（或改成「测不了」） | 该类 1 条可疑把分数压在 95.7 分；可疑项要么补证据升级成结论，要么承认测不了。 | **预计 +1.0 分（估算）** | 中 | 逐条看 ④ 里列出的可疑向量：能补 A/B 级证据的就升级；补不了的承认「测不了」，从分母里拿掉比留在可疑里更诚实。 |
| 给 虚拟化/多开 补一条 A 级不变量 | 包被改过，这一类 5 条全干净 —— 现在它不加分，但下次真被改到这一面时，只有它能救。 | **预计 +0 分（估算），这一类现在已满分，真正的收益要等下次修补才知道（待实测）** | 大 | 先按 ⑥ 的「怎么验证是不是洞」确认是真洞，再给这一类加一条 tier A 的判据（字节比对/密码学校验，而不是特征匹配）。 |
| 给 环境面 补一条 A 级不变量 | 包被改过，这一类 5 条全干净 —— 现在它不加分，但下次真被改到这一面时，只有它能救。 | **预计 +0 分（估算），这一类现在已满分，真正的收益要等下次修补才知道（待实测）** | 大 | 先按 ⑥ 的「怎么验证是不是洞」确认是真洞，再给这一类加一条 tier A 的判据（字节比对/密码学校验，而不是特征匹配）。 |

## ⑨ 附录

### 完整向量表（47 条，含干净项）

| id | 类别 | tier | 结论 | 置信度 | 权重 | 平面 | 证据 |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| `rt.tracerpid` | runtime-integrity | A | 干净（CLEAN） | 0.95 | 4 | app | TracerPid=0 (status+native agree) |
| `rt.proc.pid` | runtime-integrity | B | 干净（CLEAN） | 0.90 | 2 | app | pid=7839 (java+stat agree) |
| `rt.got.integrity` | runtime-integrity | A | 干净（CLEAN） | 0.90 | 4 | app | GOT scanned=147 bad=0 |
| `rt.maps.file_integrity` | runtime-integrity | B | 测不了（UNKNOWN） | 0.00 | 4 | app | /proc/self/mem open denied (FileNotFoundException) |
| `rt.maps.deleted` | runtime-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | no file-backed (deleted) mapping |
| `rt.memfd` | runtime-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | memfd=0 (art-jit excluded=2) |
| `rt.maps.anon_exec` | runtime-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | anon-exec=0 bytes=0 |
| `rt.maps.exec_files` | runtime-integrity | B | 可疑（SUSPECT） | 0.55 | 3 | app | exec mapping outside whitelist n=1 e0=/data/system/etc/mumu-configs/shared_libs/libhp12_x86_64.so |
| `rt.vdso` | runtime-integrity | B | 干净（CLEAN） | 0.90 | 3 | app | vdso=4096B (both views agree) |
| `rt.timing` | runtime-integrity | B | 干净（CLEAN） | 0.85 | 2 | app | openat median=691ns p99=1032ns jitter=341ns n=200 |
| `rt.thread.name` | runtime-integrity | C | 干净（CLEAN） | 0.95 | 3 | app | thread names=17 no blacklist hit |
| `rt.stack.frames` | runtime-integrity | C | 干净（CLEAN） | 0.95 | 2 | app | frames=6 no hook frame |
| `inj.elf.inline` | injection | B | 干净（CLEAN） | 0.80 | 4 | app | inline scan 4056 entries, 0 hit |
| `inj.proc.env` | injection | B | 测不了（UNKNOWN） | 0.00 | 3 | app | /proc/self/environ unreadable or empty |
| `inj.module.paths` | injection | C | 可疑（SUSPECT） | 0.60 | 4 | app | libs=248 outside=[/data/system/etc/mumu-configs/shared_libs/libhp12_x86_64.so] |
| `inj.module.marker` | injection | C | 干净（CLEAN） | 0.95 | 4 | app | libs=248 no engine marker in names |
| `inj.elf.rwx` | injection | C | 干净（CLEAN） | 0.95 | 3 | app | rwx=0 |
| `inj.frida.port` | injection | C | 干净（CLEAN） | 0.95 | 3 | app | tcp 27042/27043 closed |
| `inj.frida.socket` | injection | C | 干净（CLEAN） | 0.95 | 3 | app | no frida file/map/unix-socket trace (unix=readable) |
| `pkg.signature` | package-integrity | A | 被坐实（TAMPERED） | 1.00 | 5 | app | expect=54f81573a7dfb033… actual=[ceb1325f578f932a…] |
| `pkg.signing.v3` | package-integrity | A | 被坐实（TAMPERED） | 1.00 | 5 | app | expect=54f81573a7dfb033… actual=[ceb1325f578f932a…] |
| `pkg.cert.history` | package-integrity | A | 被坐实（TAMPERED） | 0.95 | 3 | app | expect=[54f81573a7dfb033…] actual=[ceb1325f578f932a…] (n=1/1) |
| `pkg.codepath.hash` | package-integrity | A | 测不了（UNKNOWN） | 0.00 | 5 | app | sha256=56b1ff12136895b2… (CLI compares, codePath=base.apk) |
| `pkg.zip.fingerprint` | package-integrity | A | 测不了（UNKNOWN） | 0.00 | 5 | app | zipFp=e719cec777d3f8af… (CLI compares) |
| `pkg.manifest` | package-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | appClass=io.litmus.canary.LitmusApp factory=android.app.AppComponentFactory |
| `pkg.dex` | package-integrity | B | 干净（CLEAN） | 0.95 | 4 | app | dex=1 bytes=121164 magic ok |
| `pkg.installer` | package-integrity | C | 干净（CLEAN） | 0.95 | 2 | app | installer=null (adb/sideload baseline) |
| `pkg.proc.name` | package-integrity | B | 干净（CLEAN） | 0.95 | 3 | app | proc=io.litmus.canary pkg=io.litmus.canary |
| `priv.proc.uid` | privilege | A | 干净（CLEAN） | 0.95 | 5 | app | uid=10085 (app range, views agree) |
| `priv.su` | privilege | C | 干净（CLEAN） | 0.95 | 3 | app | no su binary in 13 common paths |
| `priv.magisk` | privilege | C | 可疑（SUSPECT） | 0.55 | 3 | app | magisk trace=[path:debug_ramdisk] |
| `priv.kernel` | privilege | C | 干净（CLEAN） | 0.95 | 3 | app | kernel version has no ksu/apatch marker |
| `priv.props` | privilege | C | 干净（CLEAN） | 0.95 | 3 | app | ro.debuggable=0 ro.secure=1 service.adb.root= |
| `priv.mounts` | privilege | B | 干净（CLEAN） | 0.95 | 3 | app | mounts=113 system/vendor all ro |
| `priv.selinux` | privilege | B | 可疑（SUSPECT） | 0.75 | 3 | app | selinux permissive (enforce=0) domain=u:r:untrusted_app:s0:c85,c256,c512,c768 |
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
| `pkg.codepath.hash` | package-integrity | A | 被坐实（TAMPERED） | 1.00 | 5 | cli | facts.apk.sha256=56b1ff12136895b2… ≠ expect.apkSha256=d67c1b0aa5a43195…，装上去的 APK 不是构建产出的那个 |
| `pkg.zip.fingerprint` | package-integrity | A | 被坐实（TAMPERED） | 1.00 | 5 | cli | facts.apk.zip.fingerprint=e719cec777d3f8af… ≠ expect.zipFingerprint=0b47e92e325b5e47…，ZipEntry 指纹变了 → 包被重打包/改过内容 |

### 复现这条结果

```powershell
python cli\litmus.py score --report runs\demo-narrative\report.raw.json --expect canary\out\build-info.json
# 输出到目录：
python cli\litmus.py score --report runs\demo-narrative\report.raw.json --expect canary\out\build-info.json --save runs\demo-narrative
```

- 本次运行：`C2-repack`（-）· profile `standard` · CLI 0.1.0
- 报告来源：`offline:runs\C2-repack-20261110-164602\report.raw.json` · App 侧运行 id `f101dad5cd0e4cd2`
- 构建产物：`D:\ovo\wrok\fpa\litmus\canary\out\litmus-canary-0.1.0.apk` · 0.1.0 · 构建于 2026-11-10T09:05:01Z
- 原始数据：`runs\demo-narrative\run.json`（全量记账）与 `runs\demo-narrative\report.raw.json`（App 原始报告）
- 向量覆盖率：目录声明 53 条，本次上报 45 条；未上报 8 条（`rt.art.entrypoint`、`rt.maps.cross_view`、`rt.signal.handlers`、`inj.loader.solist`、`inj.dex.inmemory`、`priv.caps`、`pkg.split`、`virt.vapp.binder`）
- 评分一致性：App 自算 85.1 分 vs CLI 重算 85.1 分（差 0.0）—— 一致

---

由 Litmus CLI 0.1.0 生成 · schema litmus.run/1 · 评分口径与 canary/io/litmus/core/Score.java 一致。
