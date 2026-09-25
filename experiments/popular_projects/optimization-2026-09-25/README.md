# 热门项目可用性优化（2026-09-25）

本轮修复项目验证的输入范围和诊断，不增加规则，也不扩大语义支持。沿用[原始 24 项实验](../README.md)的固定提交、归档与源码；仅重测 core、actrun，不能据此改写原始队列成功率。

## 修复与实测

| 固定项目 | 修复前验证 | 普通目录扫描 .mbt | 修复后 native 计划：解析/选择 | 仍不支持的编译输入 | 最终状态 |
| --- | --- | --- | --- | --- | --- |
| moonbitlang/core | README.md 链接导致 snapshot_unavailable | 478/478 | 449/449 | 66 个 .mbt.md | scope_incomplete，exit 2 |
| mizchi/actrun | CLAUDE.md 链接导致 snapshot_unavailable | 62/62 | 56/56 | 1 个 .mbt.md | scope_incomplete，exit 2 |

- 快照忽略普通非输入文件及其文件链接；源码、literate 文件、配置、依赖文件和目录链接仍拒绝。名为 README.md 的真实目录仍遍历；悬空或无法分类的链接仍保守拒绝。
- 编译检查通过、计划已识别且快照未变化时，即使计划还包含不支持的格式，已支持的 `.mbt` 文件也遵守编译器选择。不会因为 `scope_incomplete` 回退到整个目录；未知计划、编译失败或源码变化不能取得这一资格。
- 验证报告明确给出不支持格式及数量，指向 `unsupported_files`；缺失解析、扫描期间变化也提供具体原因。未支持输入没有被删除或计为成功。
- native 范围比目录扫描少 35 个文件。这是范围校正，不是减少 35 条误报。core 全规则仍为 0 条，actrun 仍为 33 条 `syntax_hint`；默认均 0 条，不能解释为没有漏洞。
- 两份源快照的前后指纹一致。固定 moon 0.1.20260920 / moonc v0.10.14+7d59c7ec9，native 默认验证分别约 2.57、4.09 秒；这是单次耗时，不是性能基准。

来源、命令、归档/源码/分析器 SHA-256 及前后未变化状态见 [summary.json](results/summary.json)；全规则编译范围对照见 [verified-all-summary.json](results/verified-all-summary.json)。同目录 `.json.gz` 保存完整报告，绝对路径仅记录实验环境。

## 兼容性诊断与下一步

pi 对 QuickCheck 0.14.0 和 bitflow 0.4.1 的独立诊断定位到 `try?`、旧 `loop`。父任务用最小样例再次对照固定编译器与 parser 0.4.0：

| 样例 | moonc syncheck | 扫描器 |
| --- | --- | --- |
| `try?` | 接受，弃用警告 E0020 | 解析失败、exit 2 |
| 旧 `loop` | 接受，弃用语法警告 E0027 | 解析失败、exit 2 |
| 现代 `for` + `break` | 接受 | 解析成功、exit 0 |
| 故意损坏的函数声明 | 拒绝 | 解析失败、exit 2 |

[原始诊断](syntax-diagnosis.json)和 [最小样例](syntax-repros)可重跑。它证明当前编译器与独立解析库的接受集合不同，不证明类型检查、全部历史版本支持或这些构造的安全语义已实现。

```sh
python3 experiments/popular_projects/optimization-2026-09-25/reproduce_syntax.py \
  --analyzer /path/to/moon-audit --moonc /path/to/fixed-toolchain/bin/moonc \
  --output /tmp/syntax-diagnosis.json
```

下一步应先定义前端兼容层的保留语义与位置契约，再比较独立旧前端适配器、最小上游语法回移的维护成本。parser 0.4.0 的 AST 本身没有旧 Loop/Question 表示，单纯增加 parser 回退无法解决；本轮不引入大规模 vendoring，也不重写用户源码。验收要求：原始文件不变、位置一致、非法反例仍报错、已支持规则结果稳定，语义模式对未建模构造保持不完整。

`.mbt.md` 的后续支持须明确编译器选中的代码块、原始位置映射和错误示例政策，再增加格式适配；不能直接删除 `unsupported_files` 来提高成功数。

## 验收

- Moon 测试：wasm / wasm-gc / js 各 75/75，native 77/77；全目标检查、格式检查通过。
- Linux 原生交付 29/29，进程监督 4/4，CLI 回归 21/21。
- 新增五项真实入口测试覆盖普通文档链接、伪装文档的目录链接、源码/配置/依赖链接、文档后缀真实目录、包含 literate 输入时的 native/js 选源差异。
- 平台 CI 和独立代码复核以审查 PR 的最终记录为准；上述本地结果不代替其他平台验收。
