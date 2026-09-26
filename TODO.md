# moon-audit TODO 与里程碑（2026-09-26）


## 2026-09-26：跨包数据流近期交付

- [x] 确认并固化同模块跨包绑定：别名重命名、两跳转发、同名函数和参数顺序，复用现有 IR。
- [x] 修复无关函数耗尽绑定预算、失败辅助函数 IR 被后续回调复用两个问题。
- [x] String `+` 以官方声明身份和文件指纹建模；源字符串简单转义解码，未核实数值转义明确拒绝。
- [x] 固定 Luna 原生产包作为受控调用方实验；未知 HTML 属性上下文保留 partial，不宣称 Luna 漏洞或完整应用分析。
- [x] 最终本地 9 组跨包验收、独立复核、原包 15 项运行测试通过；三平台提取产物验收已接入 CI，状态见 [PR #6](https://github.com/I3eg1nner/moon-audit/pull/6) 与[跨包实验](experiments/cross_package/README.md)。

## 2026-09-26：以项目通用性为先

- [x] 普通扫描也枚举 `.mbt.md` / `.mbtx`：逐文件 unsupported、返回 2；增量和编译计划不再静默丢弃这些输入。
- [x] 两代工具链 JSONC 配置接受/拒绝 18 项对照，保留注释/尾逗号兼容并拒绝重复名称；独立最终二进制复核 12 项通过。
- [x] 多模块目录按最近模块配置决定模块身份；不继承外层标准库豁免，不把包 imports 跨包合并；配置错误保留线索并报不完整。
- [x] 两代编译器 literate 契约实验：标签选择、独立代码块、隐含测试、黑盒包角色与原始位置；没有实现或宣称 Markdown 提取支持。[实验](experiments/literate_input/README.md)
- [ ] 下一阶段 M1：统一生产 `.mbt` 输入的模块、包、后端、编译角色与源码位置表示，明确生产代码和测试代码的选择范围。
- [ ] M2：模块发现→逐模块验证→聚合工作区报告；当前多模块语法归属不代表工作区验证完成。
- [x] M3a：同模块已选生产包的受限跨包绑定/参数返回传播及失败边界（见上）。
- [ ] M3b：基于统一输入身份继续设计工作区/外部依赖的受限摘要与覆盖契约；尚未完成通用跨模块分析。

按用户决定，`.mbt.md` 检测及 Markdown 提取适配任务已从计划删除；已完成的实验保留为历史记录。

本轮代码、固定语料复测与验收记录见[通用输入改进](experiments/project_inputs/README.md)。

## 2026-09-25：合并后的热门项目与 LLM 复核

- [x] PR #1 合并 main：`075b0f3`，合并前 9 个 CI job 通过；未发布正式版本。
- [x] 下载榜/Stars 榜各 12 个固定样本：23 导入，15 语法范围完成、8 不完整、1 归档拒绝；原始压缩报告和编译抽样见[实验报告](experiments/popular_projects/README.md)。
- [x] 独立 LLM prepare/validate、自定义 OpenAI 兼容 API、配置别名、分页、精确引用、源码变更拒绝和原始报告保护。
- [x] 用户 `.env` 的真实 API 联调；两条意见为 needs_review，全部 llm_unverified；补充纯函数重复字符复现。
- [x] 原生包附带可选 Python 助手，离线 HTTP 测试进入打包验收；原生扫描仍无 Python 运行依赖。
- [x] P0 诊断：QuickCheck/bitflow 的 `try?`/旧 `loop` 为固定编译器接受、parser 0.4.0 拒绝；最小正反例已保存。
- [x] P0 适配：固定官方前端加两项上游语法回移，保留旧 Loop/Question 节点与位置；QuickCheck 34/34、bitflow 12/12，2025 QuickCheck 16→22/30。词法错误保留、原生语义拒绝和逐文件来源门禁已接入。[验收](experiments/frontend_compat/README.md)
- [ ] P0 后续：分类 2025 样本剩余 8 个失败文件；只按真实缺口扩展前端，不宣称任意旧版本兼容。
- [x] P0：修复无关文档文件链接阻断快照，保留源码/依赖/目录链接防护；不完整编译计划仍准确选择受支持文件。[固定项目重测](experiments/popular_projects/optimization-2026-09-25/README.md)
- [x] P0 调研：两代 `.mbt.md` 块标签、测试角色和原始坐标已建立实验契约；检测开发任务已删除；现有未支持范围提示保留。
- [ ] P1：复核包增加已核实的调用身份、标准库行为和直接调用点附件；不能凭模型判断补绑定。
- [ ] P1：按项目/规则抽样标注 447 条 opt-in 线索后再评价噪声；不据数量扩大默认规则。

**当前执行清单以本文为准。** 产品面向源码自编译和二进制下载用户，自己项目与第三方源码同等优先。目标是提供范围与证据明确的 MoonBit 安全检测，不追求完整复现 Tai-e。

[架构方案](docs/architecture-plan-2026-09-24.md)说明设计与限制；[suggest.md](suggest.md)保留复核判断；[旧 TODO](docs/legacy/TODO-before-redesign.md)和 [旧 IR TODO](docs/ir/TODO.md)不是当前承诺。

## 当前状态

**A–D 的有限功能、三平台交付及 LLM 复核已通过验收并合并 main（PR #1/#2）；尚未正式发布。** 默认语法扫描保留 14 条规则，仅默认启用 replace-escaping、cmark-unsafe。可选生产 `semantic` 已接入，须同时选择 `--verify-project --semantic-scope mocket-get-callbacks`，仅限 native 和核实的模型。

| 里程碑 | 当前裁决 | 可核实证据 |
| --- | --- | --- |
| M0：有限扫描器 | 已实现；用户运行不依赖 Python | [原生交付验收](scripts/native_delivery_test.py)、[进程监督](scripts/process_supervision_test.py) |
| A：范围与规则可信 | 有限范围验收通过；未知语法与未核实规则如实降级 | [14 规则审计](experiments/rule_audit/README.md)、[2025 历史项目](experiments/historical_project/README.md)、[12 格版本/后端矩阵](docs/metrics/native-version-matrix-2026-09-25.json) |
| B：真实 API 裁决 | 固定 mocket / cmark 的运行、身份与模型契约通过 | [mocket](experiments/security_chain/README.md)、[cmark](experiments/cmark_chain/README.md) |
| C：受限源码语义链 | 源码→官方绑定→顺序 IR→独立原生核心通过 | [mocket 13 项](experiments/security_chain/native-ir-2026-09-25.json)、[cmark 生产 14 项](experiments/cmark_chain/production-ir-2026-09-25.json) |
| D：可选生产接入 | 显式回调范围下本地验收通过；不宣称全项目安全分析 | [生产入口 15 项](docs/metrics/semantic-production-acceptance-2026-09-25.json) |
| 交付审查 | **三平台验收通过**，PR #1/#2 已合并；尚未正式发布 | [草稿 PR #1](https://github.com/I3eg1nner/moon-audit/pull/1)、[原生 CI](.github/workflows/native-delivery.yml) |

完成的是上述范围内的交付，不是把旧引擎的字段、别名、异常、trait 或全项目覆盖承诺全部恢复。Crescent API 编译失配和旧语法解析缺口允许继续存在，前提是状态、退出码和默认规则裁决明确。

## 已完成的可验收工作

### A：文件、版本与规则

- [x] 原生目标工具链和后端选择、`--frozen` 编译、真实文件计划、源码/配置/依赖快照、变化失效与统一 0/1/2 退出码。
- [x] JSON/SARIF/text 的覆盖报告、编译计划差异、baseline 失败保护、特殊文件拒绝与有限输出；源码和依赖读取不会把 FIFO 当普通文件。
- [x] 三套 2026 工具链 × native/js/wasm/wasm-gc 对照；2025 与 2026 两代工具链的包排除、测试文件、用户排除、空包共 8 项真实计划反例。
- [x] 未改源码的 2025 QuickCheck + 对应旧工具链：55 个原始文件指纹一致，30 个源码选择一致；16 parsed / 14 parse_failed、exit 2。结论为“编译器可验证、扫描不完整”。
- [x] 14 条规则由统一登记控制默认策略、分发、门控和报告。44 个编译形状/反例、98 个启停/覆盖/严重度一致性检查通过。[最终登记验收](experiments/rule_audit/registry-acceptance-final-2026-09-25.json)
- [x] 真实 mocket 8 项、cmark 3 项调用检查通过；Crescent 4 项因旧 lexscan 编译失败保持未核实。全部语法规则仍为 `syntax_hint`，无法核实的规则显式选择启用。
- [x] 修复复核发现的 CWE-942 严重度配置被忽略问题；误导性的 CORS、API 身份和确定性漏洞描述已降为人工复核提示。

### B/C：真实模型与独立核心

- [x] 固定 mocket 0.9.1 的实际 dispatch 8 项正反例、唯一声明绑定及库/依赖指纹；拒绝把 hover 的 `String` 名称当规范类型。
- [x] 真实源码自动降低到顺序 IR，核实 query/default/helper/HTML/text/编码等必要模型；最终 responder 返回、丢弃与覆盖用同一顺序语义计算。
- [x] 声明范围内的未知构造、模型变化、非唯一绑定、已识别的未支持 `.get` 注册形状及零可支持候选不报完整成功；其他路由类型不在该 scope 内。
- [x] cmark 0.4.8 模型复用同一 IR；`try!` 正常返回与异常终止边界核实。默认/true 的安全正文片段和 false 的未知 HTML 上下文分开建模。
- [x] cmark 生产 14 项对照通过；unsafe / 编码后 unsafe / script 位置保留 `partial_dataflow` 且 exit 2，动态参数、非默认配置和模型失配保留不完整。

### D：生产接线、预算与报告

- [x] 显式 `--analysis semantic --verify-project --semantic-scope mocket-get-callbacks`；其他后端、增量集合或缺少前提时拒绝，不暗中扩大覆盖。
- [x] 统一语法提示、`verified_dataflow`、`partial_dataflow`、路径、模型与不完整原因；baseline 不会把不完整结果清零或覆盖已有文件。
- [x] 冷/热结果一致，未知/模型失配/绑定子进程故障保留语法结果；固定 Linux 生产入口 15/15。
- [x] worker 最长 60 秒、256 查询/4 并发、每回调 IR 10000 单位；Linux 每进程 2048 MiB `RLIMIT_AS` 地址空间硬上限。资源失败与超时子孙进程清理已做 Linux 注入验收，不是全进程树 RSS 总量承诺。
- [x] 平台资源策略按实际机制披露：Windows Job Object 初始化及实际语义运行通过；macOS 50 ms 采样组 footprint 的真实超额分配测试通过，超过阈值后无存活子孙。Windows 专门提交内存超额注入未执行，不声称所有平台都完成同类注入。报告以 `memory.mechanism/scope/hard_limit` 和 `ir_units_per_callback` 明示机制。

## 已完成的交付门

- [x] Linux x86_64、macOS arm64、Windows x86_64 的真实构建、解包搬迁、项目验证、mocket/cmark 语义验收通过；Windows 文件身份和 macOS 内存监督缺陷已修复并复验。[CI](https://github.com/I3eg1nner/moon-audit/actions/runs/36105436648)
- [x] 核验平台归档 SHA-256、二进制指纹与 build-info，保存对应实现提交和日志；补充依赖模块元数据、标准许可证及第三方说明。[平台记录](docs/metrics/three-platform-acceptance-2026-09-25.json)
- [x] 子代理已独立复核规则、语义和交付；实现及证据已上传 [draft PR #1](https://github.com/I3eg1nner/moon-audit/pull/1)。用户随后授权合并，PR #1/#2 已合并 main；正式发行尚未执行。

## 后续工作：不属于本阶段的已完成承诺

1. **语言版本适配**：旧 `loop`/`try?` 已做有限适配；继续处理有真实项目证据的 `typealias` 与新 `for...in` 缺口，逐文件对照 AST、位置、规则和错误行为；不采用补丁版本白名单或吞掉解析错误。
2. **新 API 模型**：先固定可编译库、运行效果、绑定和依赖指纹，再决定增加语义。Crescent、rabbita/WebSocket 不能复用合成同名 API 作为真实证据。
3. **控制流与堆**：分支、异常、默认参数、对象别名、trait/async 仅在具体安全链确需时逐项验收。Python/旧核心规格不等于这些能力已经生产化。
4. **项目级覆盖**：注册调用可达性、中间件变更、更多路由注册形状是新范围；现有 `.get` 回调成功不证明全项目安全。
5. **成本与发布维护**：扩大固定真实项目测量；版本升级先过编译、解析、绑定、模型、报告和资源门禁，再变更支持声明。

停止条件不变：若新链必须依赖大量案例专用 AST 回退才能成立，停止扩张求解器，优先保持现有范围、拒绝边界和交付可复现。
