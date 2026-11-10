# CONTRIBUTING

## 提交规范

标题一律 `type: 描述` 形式：

- `type` 用英文小写：`feat` / `fix` / `chore` / `docs` / `refactor` / `test` / `ci` / `perf`
- 描述用中文，一句话说清「改了什么」，不写「修改了一些问题」这种空话
- **不使用括号**（全角 `（）` 与半角 `()` 都不出现），因此**不写 `type(scope):` 形式**
- 标题里不要堆多个改动点；一个提交只做一件事，拆不开就说明提交粒度错了

```
✅ feat: 应用内交互与详情卡
✅ fix: 非法 verdict 不再计入 clean
✅ chore: 初始化仓库
❌ feat(ui): 应用内交互与详情卡        ← 有 scope
❌ fix(core): 修复一个 bug              ← 有 scope 且描述空洞
```

**提交前先确认标题**：动手前把拟好的标题发出来，确认后再执行 `git commit`。

## 首个提交

仓库的第一个提交固定是 `chore: 初始化仓库`，只放工程骨架：
`.gitignore`、`.gitattributes`、`LICENSE`、空的 `README.md`。
功能与文档一律放在后续提交里 —— 否则 `git log` 的第一屏就是一大坨，读不出这个仓库是怎么长出来的。

## 提交粒度

按**目录边界**切，一个提交只碰一个子系统（`canary/` / `cli/` / `docs/` / `tools/`）。
原因是这个仓库由多个并行工作面推进，按目录切既好 review 也好 revert。

## 改动前必读

| 你要改 | 先读 |
| --- | --- |
| 检测向量 | `docs/04-契约.md`（冻结契约）+ `docs/02-探针目录.md` |
| 评分逻辑 | `docs/03-评分模型.md`（`cli/litmus_score.py` 是权威实现） |
| 交互 / 报告 | `docs/07-交互与报告规范.md`（I1–I10 / R1–R8 是验收指标） |
| 构建链 | `canary/build.ps1`（无 gradle，`aapt2 + javac + d8 + clang++ + apksigner`） |

## 提交前必须全绿

```powershell
python tools\lint_vectors.py          # 契约门禁（tier C 不许判 TAMPERED）
python tools\gen_vector_docs.py --check  # VectorDocs.java 与 vectors.json 同步
python tools\coverage.py              # 覆盖度审计（看缺口有没有扩大）
python cli\litmus.py selftest          # 137 项断言
pwsh -File canary\build.ps1 -NoNative # 至少在无 native 路径下能构建
```

## 代码风格

- **零第三方依赖**是硬约束：`import` 只允许 `android.*` / `java.*` / `org.json` / `io.litmus.*`
- UI 全部代码构建（不写 layout xml），视觉 token 见 `docs/07` §5
- 注释写**为什么**，不写「这里遍历列表」这种复述代码的注释
- native 只做机械取证，判定一律在 Java 侧（改判据不该重编 `.so`）
