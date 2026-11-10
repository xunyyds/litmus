# Litmus · 试金石

<p align="center">
  <b>把「过检测」变成一个可复现的分数</b><br/>
  <i>Tamper-detection benchmark for Android. Patch the canary, then weigh what's left.</i>
</p>

<p align="center">
  <a href="#"><img alt="Platform" src="https://img.shields.io/badge/Android-8.0%20~%2016-3DDC84"></a>
  <a href="#"><img alt="Vectors" src="https://img.shields.io/badge/Vectors-53%20catalog-6C5CE7"></a>
  <a href="#"><img alt="License" src="https://img.shields.io/badge/License-MIT-2F81F7"></a>
  <a href="#"><img alt="Status" src="https://img.shields.io/badge/Status-v0.1%20skeleton-2EA043"></a>
</p>

---

## 它是什么

一句话：**我们发布一个「正常包」，你随便修补它；我们告诉你，我们还能看见多少。**

- 你拿 `canary`（一个普通 Android 应用，内嵌检测内核）去做任意操作：重打包、换签名、注入 Frida、上 LSPosed、塞 Zygisk 模块、丢进 VirtualApp、跑在模拟器里……
- 检测内核跑 **53 条检测向量**（六个类别），每条只输出「事实 + 结论」。
- CLI 汇总成 **Litmus Score（0–100）**，并给出两份最有价值的清单：
  - **盲区 Blind Spot**：你确实改了包，但某一整类检测**一条都没抓到** → 我们的洞。
  - **误报 False Positive**：包其实没动，却在某个向量上被冤枉 → 这个环境里这条检测不可信。
- 全程产物是稳定 schema 的 `run.json`，**能进 CI、能比版本、能做回归**。

> 名字来自**试金石**——检验黄金成色的那块石头：它不改变金子，只告诉你成色还剩多少。
> 我们对你的补丁做的是同一件事：不动你的包，只量它还留着多少能被认出来的痕迹。
> 英文 `litmus` 取「石蕊试纸」之意（`litmus test` 本身就是「判定标准」），
> 也和中文名共享同一个隐喻：**一测就知道成色**。

---

## 为什么不是又一个 Momo

Momo / Ruru 那类工具解决的是「**我这台机器脏不脏**」，给的是红绿灯。它们的问题不在能力，在**形态**：

| 维度 | Momo / Ruru 类 | Litmus |
| --- | --- | --- |
| 输入 | 你的设备环境（root / hook / 模拟器） | **你修补过的包** + 设备环境，两个平面 |
| 输出 | 一串红绿灯 | **分数 + 类别分 + 盲区 + 误报**，稳定 JSON |
| 可复现 | 靠人截图 | `run.json`，同 schema，可 diff、可进 CI |
| 误报 | 无基线概念，模拟器上满屏红 | **基线归一**：先用干净机跑一遍，只算「你额外引入的脏」 |
| 扩展 | 闭源、判据不公开 | 向量注册表 + 冻结契约，加一条向量只要实现一个 `Probe` |
| 目标 | 让人知道「脏」 | 让「过检测」变成**工程量与成本曲线**（哪类要改多少东西才能打到 CLEAN） |

一句话差别：**Momo 告诉你结果，Litmus 给你一个能拿去做回归的仪表盘。**

---

## 三个平面（这是整个设计的地基）

```
┌──────────────────────────────────────────────────────────────────────┐
│  Plane SELF —— 检测内核跑在被修补的包里面（io.litmus.core）             │
│    能看见：自己的内存布局、函数入口字节、签名、dex、清单属性、线程      │
│    看不见：自己被 hook 之后「本该是什么样」—— 除非有外部参照            │
├──────────────────────────────────────────────────────────────────────┤
│  Plane DEVICE —— 设备环境面（Momo 那套）                              │
│    能看见：root / 模拟器 / 注入框架的包与文件 / 属性 / 挂载             │
│    天生误报高 —— 所以只出 SUSPECT，永远不单独判死                       │
├──────────────────────────────────────────────────────────────────────┤
│  Plane CLI —— 进程外记账（cli/litmus.py）                              │
│    能看见：APK 文件本身的哈希、构建期烘进去的期望值、历史基线           │
│    这是唯一「包改不了」的平面 —— 也是分数的最终权威                     │
└──────────────────────────────────────────────────────────────────────┘
```

为什么必须三层：**检测器自己就在被修补的包里**，用户可以 hook 它、伪造它的结论。
所以凡是能被伪造的结论都不能是最终依据：

- App 侧只产出**可交叉验证的事实**（`facts`）与**带 tier 的结论**（`signals`）；
- 最终「包到底有没有被改」由 CLI 用**构建期期望值**在进程外比对（`pkg.codepath.hash` / `pkg.zip.fingerprint`）；
- 这个边界我们写在明面上：**本地方案能挡住低成本伪造，挡不住完整重放**。要更强就得上服务端 nonce + 硬件密钥证明（路线图 v0.3）。

---

## 通吃靠什么

**不靠特征，靠不变量（invariant）。**

| 你做的手脚 | 一定被破坏的等式 | 对应向量 |
| --- | --- | --- |
| Frida 注入 | 进程里出现匿名可执行段 / `TracerPid≠0` / 线程名异常 / memfd 映射 | `rt.maps.anon_exec` `rt.tracerpid` `rt.thread.name` `rt.memfd` |
| LSPosed / Xposed | ART 方法入口被改 → 函数入口运行时字节 ≠ 磁盘字节 | `inj.elf.inline` `rt.got.integrity` |
| Zygisk / KernelSU | 模块注入必然改 `/proc/self/maps` 的 file-backed 段 | `rt.maps.file_integrity` `rt.maps.deleted` |
| 重打包 / 换签名 | 签名链、APK 内容哈希、ZipEntry 顺序必变 | `pkg.signature` `pkg.codepath.hash` `pkg.zip.fingerprint` |
| VirtualApp / 双开 | 宿主路径特征 + 进程名 + 包可见性异常 | `virt.vapp` |
| 模拟器 | Build 指纹 + 文件 + 硬件特征三面同时异常 | `virt.emulator.*` |

对应的反面：**「包名里有 `de.robv.android.xposed`」这种判据只能算 tier C**，因为装了 LSPosed 不代表这个应用被注入。
契约里这条是硬约束（§2.2 / §5）：**tier C 永远不许单独判 TAMPERED**。这正是「通吃」不退化成一锅特征匹配大全的原因。

---

## 界面（v0.2 起）

三个页签 + 一张详情卡 + 一条历史，全部手绘、零第三方依赖（`import` 只有 `android.*` / `java.*` / `org.json`）。

| 总览 | 应用内 HTML 报告 |
| --- | --- |
| ![总览](docs/images/ui-home.png) | ![报告](docs/images/ui-html-report.png) |

- **总览**：环形分数 + 状态句 + 最近 5 次运行（点一下切回那次，长按删除）
- **向量**：筛选 chips（全部/篡改/可疑/未判）+ 搜索 + 分组列表；点任意一行 → 底部详情卡
- **详情卡**：判据 / 证据 / 万一意味着什么 / 怎么绕过，文案来自 `VectorDocs`（与报告同一套说法），可「复制这一条」
- **⋮ 菜单**：设备信息 / 分享摘要 / 复制 JSON / 导出文件
- `score == null` 时环只画底环、显示「—」与「无法评分」，**没有任何路径会显示 100**

## 报告（人话优先）

`report.md` / `report.html` 是九段式叙事，不是表格堆砌：

```
① 一句话结论  ② 三个数字  ③ 这次改了什么  ④ 逐类判断  ⑤ 被坐实的问题
⑥ 我们看不见的地方  ⑦ 环境噪声  ⑧ 怎么让分数上去  ⑨ 附录
```

例如 `C2-repack`（换签名 + 塞文件）的开头是：

> 这个包**被改过**（内容哈希、打包指纹和签名都与构建产物对不上），其中「包完整性」掉得最狠（36.1 分，5 条被坐实）。
> 但「虚拟化/多开和环境面」一条都没抓到 —— 这几类对本次修补是失明的，见 ⑥。

⑥ 对每个盲区都给「为什么可能是洞」+「怎么验证是不是洞（3 个可执行步骤）」；
⑧ 的行动清单带**预估收益与成本**。样例：[examples/report-real-clean.md](examples/report-real-clean.md) · [HTML 版](examples/report-real-clean.html)（真机 47 条向量）。
想看「包被改过 + 盲区」那版，不用设备也能生成：`python cli/litmus.py demo --fixture b`。

## 快速开始

```powershell
# 0) 环境自检（adb / 设备 / 构建产物）
python cli\litmus.py doctor

# 1) 构建靶包（自举签名密钥，产出 out\litmus-canary-0.1.0.apk + build-info.json）
pwsh -File canary\build.ps1 -Install -Serial emulator-5554

# 2) 干净基线：先量一次「这台机器本来有多脏」
python cli\litmus.py run --serial emulator-5554 --label C0-baseline

# 3) 修补它（换签名 / 注入 / 上模块……），然后重新测
python cli\litmus.py run --serial emulator-5554 --label C1-frida `
       --framework frida --baseline runs\C0-baseline-*\run.json

# 4) 多轮对比 + 出报告
python cli\litmus.py matrix --runs runs
```

产物：`runs\<label>-<ts>\{report.raw.json, run.json, report.md, report.html}`。

### 已经跑通的对照（v0.1 · MuMu / Android 12 / `emulator-5554` · 共 10 次运行）

| 运行 | 包状态 | 分数 | 发生了什么 |
| --- | --- | --- | --- |
| 官方包 ×8（`C1-*`） | 未改动 | **90.7 – 95.1** | native 在位：inline hook 扫描 **4056 个函数入口 · 0 命中**，GOT **147 槽 · 0 异常**，`openat` 中位 681ns。同一份包同一天两次能差 4 分——设备噪声是真的，所以基线不是可选装饰 |
| 重打包 ×4（`C2-*`，`tools/make-repack.ps1` 换签名 + 塞文件） | 已改动 | **85.5 – 88.1** | 包完整性固定 **100 → 36.1**（5 条 A 级 TAMPERED，含 CLI 平面两条），**盲区固定 2 类**：虚拟化 / 环境面 |

第二行才是这产品要回答的问题：**你改了这个包，但我们有两大类完全没看见**。
盲区清单会把它点名到具体向量，而不是含糊地说一句「部分检测通过」。
反过来，8 次官方包运行全部 **0 盲区 / 0 误报**——这说明分数不是靠运气。

---

## 目录结构

```
litmus/
├─ docs/           00 定位 · 01 架构 · 02 探针目录 · 03 评分模型 · 04 契约(冻结) · 05 框架矩阵 · 06 路线图 · 07 交互与报告规范
├─ schema/         app-report / run / vectors 的 JSON Schema
├─ canary/         靶包：Android 工程 + 手工构建脚本（无 gradle）
│   ├─ src/io/litmus/core/       检测内核（可整体搬进任意应用）
│   │   └─ probes/              六类向量实现
│   ├─ src/io/litmus/canary/     靶包 UI（记分板）
│   ├─ jni/                     native 探针（maps / ELF / inline hook 扫描）
│   └─ build.ps1                aapt2 + javac + d8 + apksigner
├─ cli/            litmus.py：adb 驱动 · 评分 · 盲区 · HTML/MD 报告
└─ tools/
```

---

## 判据一览（摘要，完整见 [docs/02-探针目录.md](docs/02-探针目录.md)）

| 类别 | 代表向量 | tier |
| --- | --- | --- |
| 运行时完整性 | `rt.tracerpid` `rt.maps.file_integrity` `inj.elf.inline` `rt.got.integrity` `rt.timing` | A/B |
| 注入痕迹 | `rt.memfd` `inj.elf.rwx` `inj.frida.*` `inj.proc.env` | A/B/C |
| 包完整性 | `pkg.signature` `pkg.codepath.hash` `pkg.zip.fingerprint` `pkg.dex` | A |
| 提权面 | `priv.su` `priv.magisk` `priv.kernel` `priv.props` `priv.mounts` | C |
| 虚拟化 | `virt.emulator.*` `virt.vapp` `virt.multi.user` | C |
| 环境面 | `env.debuggable` `env.developer` `env.proxy` | A/C |

---

## 状态

| 内容 | 状态 |
| --- | --- |
| 冻结契约 v1（6 类 / 53 向量 / 3 平面 / 3 份 JSON schema） | ✅ |
| 检测内核骨架（Runner / Snapshot / Score / Registry） | ✅ |
| 基线 7 条向量（Java）+ native 基线（maps/TracerPid/threads/timing） | ✅ |
| **45 / 53 条向量实现**（A 9 · B 15 · C 21），契约 lint 全过 | ✅ |
| native 硬检测：inline hook 字节比对（ELF dynsym）+ GOT 落点 + 段完整性 | ✅ |
| 靶包 UI + 手工构建脚本（无 gradle） | ✅ |
| CLI 记分 / 盲区 / 误报 / HTML 报告（selftest 84 项断言） | ✅ |
| 剩余 8 条向量（`rt.art.entrypoint` `inj.loader.solist` `priv.caps` …）、独立 detector APK | 🚧 v0.2 |

---

## 合法使用

本项目用于**验证你自己应用 / 你自己补丁方案的抗篡改能力**，靶包是我们自己发布的、不含任何第三方代码的测试应用。

- ✅ 给自研加固/壳/补丁框架做回归、给客户证明「你的改动会被我们检出」
- ✅ 教学、CTF、安全研究、论文复现
- ❌ 用它去绕过第三方的真实保护、去未授权地修改他人应用

检测结果与取证数据只落在本机 `runs/` 与设备 `Android/data/io.litmus.canary/`，不上报任何服务器。

---

## License

MIT · 见 [LICENSE](LICENSE)。
