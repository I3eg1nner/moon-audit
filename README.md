# moon-audit

面向下载源码自行编译、或下载原生二进制的用户，检测自己的 MoonBit 项目和第三方源码。当前为 **0.5.0-dev**：默认提供有限语法扫描，另有**显式限定范围的可选安全数据流分析**。零发现不等于项目安全；报告同时给出发现、证据和未分析范围。

## 当前能做什么

| 模式 | 已实现能力 | 边界 |
| --- | --- | --- |
| 默认 `syntax` | 14 条语法提示规则、文本/JSON/SARIF、baseline、文件列表扫描 | 仅默认启用 `CWE-116/replace-escaping`、`CWE-79/cmark-unsafe`；其余显式选择。全部为 `syntax_hint`，不证明 API 身份或漏洞 |
| `--verify-project` | 用项目自己的工具链编译检查、按后端文件计划选源、核对源码和依赖快照 | 编译通过不代表分析器能解析全部语法；不自动安装或升级项目依赖 |
| 可选 `semantic` | 固定 mocket 查询参数→String helper→最终返回 HTML responder；复用同一 IR 接入固定 cmark 渲染模型 | 仅 native、声明的 `mocket-get-callbacks` 范围与核实的模型指纹；不证明注册可达性、中间件行为或浏览器可利用性 |

规则默认策略、分发和报告能力由同一登记生成。`--rule` 可选择其余规则，但不会把名称匹配升级为真实绑定。逐条依据见 [14 条规则审计](experiments/rule_audit/README.md)。旧 CFG/污点 DSL/LLM/pipeline 入口已移除；旧选项和配置会被拒绝。

### 2026-09-28：移除 panic/cast 两条规则的未证实静默豁免

`CWE-248/panic-reachable` 和 `CWE-704/unsafe-cast` 此前会在无任何证明时静默漏报候选：guard-else 包含、`unwrap` 等函数名、消息含 `unreachable`/`unimplemented`/`invalid` 等关键词、零参 `panic()`、`.wasm/.js/.native` 文件名后缀，以及整文件 extern 文本与 moonbitlang 标准库模块名门控。这些启发式均不证明不可达或身份，且已证实会隐藏真实可达的终止（含 `.native.mbt` 实际编入 native 目标的位点）。现已全部移除：这两条规则报告其识别的全部语法形式，仍为 `syntax_hint`，不证明漏洞。

影响与边界：显式选择这两条规则时候选数会明显增加（本地冻结真实语料 342→911，均为覆盖变化，不是误报下降也不是新漏洞）；默认扫描仍只有上述两条默认规则；同名自定义函数/方法仍只产生名称提示；后端透选仍由编译器文件计划决定而非文件名推断；`--config` 禁用、排除策略、baseline 照常生效；程序反证流水线未变。原30条真实样本位点全部保留，可信排除仍为0。运行时与语料验收见 [panic/cast 覆盖实验](experiments/panic_cast_coverage/README.md)。

前端使用固定官方 parser 0.4.0 加窄范围兼容补丁，已支持旧 `try?`、`loop` 的语法扫描；2026-09-28 起以 `identifier-compat-v1` 精确容纳官方编译器接受的六个保留字标识符（method/alias/local/final/ref/module，仅丢弃其 Reserved_keyword 诊断、token 不变），报告显示 `0.4.0+moon-audit-legacy.2`。其它保留字与非法词法仍失败关闭；未建模的旧构造在语义模式仍报不完整。[真实新版/2025 项目对照与边界](experiments/frontend_compat/README.md) · [保留字标识符契约与 BioSeqs 复扫](experiments/identifier_compat/README.md)

普通目录扫描识别 `.mbt`、`.mbt.md`、`.mbtx` 输入；目前仅解析 `.mbt`，其余逐文件记录为 `unsupported` 并返回 2，已有发现保留。增量列表、排除策略和已识别的编译计划同样约束这些输入。嵌套模块以各自最近的 `moon.mod` / `moon.mod.json` 判断模块身份，止于扫描根；包导入仍只取本包配置。这不等于自动编译整个工作区。[输入契约与复测](experiments/project_inputs/README.md)

## 快速示例

`examples/vulnerable_server.mbt` 包含一个带有路径遍历和 CRLF 注入问题的最小 Web 处理器示例。构建后运行：

```bash
moon run src/main -- --rule CWE-22/path-concat --rule CWE-113/crlf-injection examples/
```

预期输出 2 条发现（1× CWE-22 路径拼接，1× CWE-113 动态头部值），安全函数不会触发告警。

## 本地使用与构建

用户运行原生二进制无需 Python。默认源码扫描也无需目标项目工具链；项目验证和语义模式需要项目工具链及已准备的依赖。

```bash
moon-audit --format json /path/to/project
moon-audit --rule CWE-113/crlf-injection /path/to/project
moon-audit --verify-project --project-toolchain /path/to/project-moon \
  --target native --format sarif -o results.sarif /path/to/project
moon-audit --verify-project --declaration-evidence --project-toolchain /path/to/project-moon \
  --target native --format json /path/to/project
moon-audit list-rules
```

`--project-toolchain` 指向含 `bin/moon` 或 `bin/moon.exe` 的根目录。互斥选项 `--project-moon /path/to/moon` 可指定可执行文件并保留调用者环境；都不指定时从 PATH 查找。工具链选项须配合 `--verify-project`，参数按数组传递，不接受 shell 命令字符串。

分析器构建固定 moon `0.1.20260920` / moonc `v0.10.14+7d59c7ec9` 和本机 C 编译器，依赖见 [moon.mod](moon.mod)。构建版本独立于待检测项目版本。下载安装器使用的编译器归档 ID 是 `0.10.14+7d59c7ec9`，不是 moon 的日期版本。

```bash
moon update
moon check --target all --deny-warn
moon build --target native --release
# 产物：_build/native/release/build/src/main/main.exe
moon run src/main -- --format json /path/to/project
```

Linux x86_64、macOS arm64、Windows x86_64 的原生开发包可从[原生交付 CI](https://github.com/I3eg1nner/moon-audit/actions/workflows/native-delivery.yml)的 Artifacts 下载，请选择对应提交已通过的构建。归档包含 build-info、依赖许可证及兼容前端修改说明。[初始三平台验收记录](docs/metrics/three-platform-acceptance-2026-09-25.json)保留历史证据；当前仍为开发版，尚未正式发布。

## 可选 LLM 复核与热门项目检查

新增独立 Python 助手，支持自定义 OpenAI 兼容 API：先从 JSON 报告准备有限源码上下文，再核验模型引用、源码指纹和发现 ID。支持标准环境变量及 `Base_URL` / `Model` / `API_KEY`；`.env` 必须显式指定。所有模型意见均为 `llm_unverified`，不改变静态证据或 baseline。原生包附带 `extras/` 助手；仅此可选功能需要 Python 3.12+。[使用与边界](docs/llm-review.md) 编译器关联的数据流告警现在可附完整相关函数、IR 和编译单位证据，支持带附件 ID 的跨文件引用，并在请求前后复验配置、依赖和源码集合；证据不足仍明确保留未知。 [真实模型对照与成本](experiments/llm_evidence/README.md)。

普通语法告警也可使用 AST 所在完整声明或小文件全文，同文件源码共享附件，保留逐条引用校验和明确回退；`--context-mode window` 可生成对照。固定 247 条待审项的复评显示判断改善有限，仍需补实际绑定与 API 契约。[上下文优化、失败分母与独立复核](experiments/llm_syntax_context/README.md)

已固定 Mooncakes 下载榜和 GitHub stars 榜各 12 个版本进行检查：23 个样本导入成功，15 个完成所请求的语法范围、8 个不完整，另 1 个归档因外部符号链接未导入。默认发现 2 条，全部规则发现 447 条语法线索；这些数量不是漏洞数。[完整结果、LLM 联调及后续优先级](experiments/popular_projects/README.md)

2026-09-26 重测相同 23 个已导入样本：4,541 个此前可解析 `.mbt` 和 2 条默认发现保持不变，18 个项目新披露 306 个未支持输入；4 项完成、19 项不完整。这是输入范围披露的修正，不代表解析退步或漏洞增加。[重测](experiments/project_inputs/README.md)

后续已修复 core/actrun 的文档链接验证阻断，并使不完整报告继续遵守编译器文件计划；两者的 `.mbt.md` 缺口仍明确报不完整。[优化实测](experiments/popular_projects/optimization-2026-09-25/README.md)

## 可选语义检测

```bash
moon-audit --analysis semantic --verify-project \
  --semantic-scope mocket-get-callbacks \
  --project-toolchain /path/to/project-moon --target native \
  --format json /path/to/project
```

当前范围是核实到 mocket `0.9.1` 的 `.get("固定路径", 内联单形参回调)`：查询来源、受支持的 String 参数/返回传播、局部顺序覆盖、HTML 文本编码和最终 responder 返回。创建后丢弃或覆盖的 responder 不算实际输出。成立前提包括注册代码会执行、中间件不改变 responder/content-type 语义；报告不证明这些前提。`--changed-files`、其他后端或省略显式 scope 都不能用于语义模式。没有可支持回调也返回不完整。

同一模块内、由目标编译器选中的生产包可跨包绑定和传递 String 参数/返回值，支持导入别名、同名函数区分及核实到固定 core 声明的 String `+`。只查询到达的回调/辅助函数体；失败分析生成的 IR 不会被其他回调复用。未建模外部依赖、泛型/方法/分支/循环等仍不完整；这不是任意依赖或整个工作区分析。字符串常量只解码已验证的简单转义，数值转义保持不支持。[跨包验收与真实包边界](experiments/cross_package/README.md)

项目验证另行披露 `compilation_units`：模块、包、包类型、目标后端、生产/白盒/黑盒角色及各输入的 source/doctest 模式。语义入口只使用生产 source，跳过内联 `test`；IR 函数可通过 `function_units` 追溯到单位和源码。普通语法扫描仍遵循自己的选源策略。涉及 `#cfg` 的注册或辅助函数明确不完整；未知编译参数、源码替换和快照未覆盖的输入也不冒充已验证上下文。

回调和辅助函数先做结构转换，整个函数体可表示后才查询官方绑定。不支持的结构不会先消耗大量查询；预算保持 256 次、4 并发、60 秒，支持语法较多的项目仍可能耗尽预算。这些措施没有增加分支、堆或任意外部依赖分析能力。[编译上下文及性能实验](experiments/compilation_context/README.md)

固定 cmark `0.4.8` 的 `try! render(...)` 复用同一 IR：核实的默认/显式 `safe=true` 可作为 HTML 正文片段处理；它不是通用字符串编码器。`safe=false`、编码后再 unsafe 渲染或脚本上下文保留已知路径为 `partial_dataflow`，并返回 **2**。动态安全标志、非默认配置、模型/依赖指纹变化和未支持构造都不会被当成安全结果。[cmark 生产入口证据](experiments/cmark_chain/production-ir-2026-09-25.json)覆盖 14 项对照。

JSON 顶层与 SARIF run properties 的 `semantic_analysis` 保存声明范围、绑定、模型、路径和不完整原因。完整受限路径使用 `verified_dataflow`，部分路径使用 `partial_dataflow`；它们都不是已证实漏洞。生产报告 schema 为 `moon-audit.scoped-dataflow.v1`，`support=validated_callback_subset`；是否完成请求以 `status` 和显式 scope 为准。独立实验 probe 仍使用实验 schema。

语义 worker 的墙钟上限为 **60 秒**（用户 `--timeout-seconds` 更小时取较小值），最多 **256 次绑定查询、4 个并发查询**，每回调 IR 预算 10000 单位。内存监督按平台区分：

| 平台 | 2048 MiB 的作用范围与机制 |
| --- | --- |
| Linux | 每进程地址空间硬上限，使用 `RLIMIT_AS`；不是进程树的总 RSS 上限 |
| Windows | 每进程提交内存硬上限，使用 Job Object；不是进程树的总 RSS 上限 |
| macOS | 每 50 ms 采样进程组各进程的 physical footprint 并求和；超过阈值或无法采样时终止整个组。属于采样阈值，可能短暂超额，不是硬地址空间上限 |

报告的 `budget.memory` 包含 `mechanism`、`scope`、`hard_limit`，IR 字段为 `ir_units_per_callback`。超时、资源限制或子进程失败保留可获得的语法结果，标记不完整。Linux 生产入口 [15 项验收](docs/metrics/semantic-production-acceptance-2026-09-25.json)包含冷/热一致性、baseline、未知边界及资源故障。macOS 的实际进程组超额分配与子孙清理测试已通过；Windows 长短路径、大小写身份及 13 组语义验收通过。Windows 提交内存超额的专门注入尚未执行，不与 Linux/macOS 的内存故障证据混称。

### 2026-09-30：可选声明观察（非证明）

`--declaration-evidence`（需 `--verify-project`）在实际验证的后端/编译单位上下文中为每条 finding 收集官方 `peek-def` 声明位置与有界声明摘录（项目/工具chain 根内），报告嵌入 `declaration_evidence`。恒 `filter_eligible=false`：它不是安全证明、不改变严重度、不赋予过滤资格，也不替代程序反证 verifier；默认扫描不产生任何 IDE 查询。原始30复检与边界见 [declaration_evidence 实验](experiments/declaration_evidence/README.md)。

## 报告、退出码和 baseline

支持 `--format`、`--output`、`--config`、`--severity`、可重复 `--rule`、`--changed-files`、`--baseline`、`--fail-on-error`、`--verbose`、`--quiet`。语法增量文件列表不分析受影响调用者，空列表主动检查零文件。

```bash
moon-audit generate-baseline -o baseline.json /path/to/project
moon-audit --baseline baseline.json /path/to/project
moon-audit generate-baseline --verify-project \
  --project-toolchain /path/to/project-moon -o baseline.json /path/to/project
```

- `0`：所请求范围完成，未触发告警退出策略；可以仍有发现，不表示项目安全。
- `1`：`--fail-on-error` 命中 Error 级发现。
- `2`：参数、读取、解析、验证、语义范围/资源或报告写入失败；已有发现可以保留。

baseline 只抑制记录的发现，不能清除不完整状态；不完整扫描不会覆盖 baseline。

`analysis_manifest` 记录逐文件 `parsed`、`parse_failed`、`read_failed`、`unsupported`、`skipped`，及逐规则 `evaluated`、`disabled`、`gated_out`。语法 `evaluated` 仅表示规则执行，`gated_out` 依据导入提示而非 API 身份。`files_selected` 与 `files_parsed` 分开计数；旧 `files_scanned` 表示已读取并尝试解析。排除目录与测试文件在选择策略中披露，不计为已检查内容。

`project_verification` 记录工具链、后端、编译选源、策略排除/缺失文件和 SHA-256 快照账本指纹。验证执行 `moon check --frozen` 及同工具链文件计划，可能写入构建缓存。默认 `--timeout-seconds 300` 限制每次外部命令，不是全项目总预算；stdout/stderr 各限 16 MiB。快照最多 100000 个相关文件、单文件 16 MiB、累计 256 MiB，遍历检查 30 秒；特殊路径、源码或依赖变化使验证失效。

## 多模块目录聚合与 moon.work 联合计划（workspace 子命令）

`moon-audit workspace` 是原生（无 Python 依赖）的多模块入口，两种模式：

```bash
# M2a：独立模块目录聚合——发现目录树下每个 moon.mod/moon.mod.json 模块根，
# 逐模块执行与单模块命令相同的验证+扫描流水线
moon-audit workspace --mode modules --project-toolchain /path/to/toolchain /path/to/dir

# M2b：现代 moon.work 联合计划——在选中的 workspace 根执行一次
# moon check --frozen + 一次 dry-run，按 -workspace-path 归属成员单位
moon-audit workspace --mode joint --project-toolchain /path/to/toolchain /path/to/workspace
moon-audit workspace /path/to/workspace   # auto：有 moon.work 走 joint，否则 modules
```

- 模块身份 = 相对根路径 + manifest SHA-256（同名不同目录仍是不同模块）；`.git/.mooncakes/_build/.recovery` 与点前缀目录按披露策略排除；嵌套模块（含无效 manifest）是显式扫描边界，父模块回退语法扫描不会重复子模块发现。
- `--mode joint` 成员状态：`compiler_verified` / `unverified_under_failed_workspace_check`（一次联合检查失败使所有成员编译状态失效，仍保留各成员语法扫描与发现）/ `no_selected_units`（含空成员表）/ `missing_member_manifest` / `invalid_member_manifest` / `duplicate_module_names` / `external_member_outside_supported_scope`（外部成员阻止联合编译，不声称闭包）/ `unsupported_member_path`（符号链接/特殊成员根不扫描）。legacy `moon.work.json` 由已装工具链不支持，仅披露不转换；两种格式并存时现代 `moon.work` 生效。
- 环境选择如实记录并透传：`MOON_WORK`（unset/空/auto=自动；off=禁用；路径=固定）、`MOON_NO_WORKSPACE`（除精确 `0` 外禁用，`MOON_WORK` 显式设置时忽略并告警）。本工具绝不静默设置 `MOON_WORK=off`。
- 预算区分总预算（`--workspace-timeout-seconds`，默认 900）与每次命令超时（`--timeout-seconds`）：每条受监督编译命令在启动前按剩余预算毫秒级截断（硬取消），扫描按文件协作停止并保留已产发现，预算耗尽后剩余模块记 `not_run_budget`；一次有界同步 manifest 读取/解析与最终快照仍可能在期限后完成，因此总预算不是全进程硬墙。
- 聚合退出码 2>1>0：任何不完整/发现错误/未执行模块为 2；仅在全部完成且 `--fail-on-error` 命中 Error 发现为 1；0 不是安全声明。
- JSON 使用独立 schema `moon-audit.workspace.v1`（内嵌每个成员的完整单模块报告）；text 逐模块分节标注状态；SARIF 每模块一个 run（保留 artifact 身份与失败 invocation 通知）。LLM 复核继续按模块消费单模块子报告。
- 不支持组合在扫描前显式拒绝：`--analysis semantic`、`--changed-files`、`--baseline` 与 workspace 组合均直接报错。
- 显式 `--config` 为全部模块共享（文档化行为）；该策略文件若位于被扫描树之外，则不属于编译器根快照的失效范围，不声称任意外部策略冻结。
- 默认单模块递归行为不变：`moon-audit /path` 仍按原语义递归。

验收：`python3 scripts/workspace_test.py` 共 44 例（19 M2a：独立模块成败/嵌套边界/重名/无效与歧义 manifest/每模块配置拒绝/变更失效/符号链接与 FIFO/零模块/预算截断/退出码与环境选择；25 M2b：联合计划成员状态、`.`/source=src/版本覆盖/native 与 js、失败联合保留发现、未列/已列无效嵌套、外部与符号链接成员、去重/重名/缺失/空成员/绝对路径、legacy 与双格式、环境选择、FIFO/重复键/成员上限/成员集变更）。对照的官方 moon.work 契约证据见 [experiments/workspace/README.md](experiments/workspace/README.md) 的 C01–C19 映射。另有独立的提取重定位/无 Python/无工具链验收（空 PATH 下 exit 2、逐模块 toolchain_unavailable、回退扫描保留发现），以及 native-delivery CI 新增 workspace 步骤（平台能力缺失时按能力跳过）。

## 检测不同版本的 MoonBit 项目

目标工具链负责判断项目是否能编译，打包的 parser 负责解析供分析使用，两者的兼容性分别报告。`moon.mod` 的版本是模块版本，不用来推断编译器版本。新 `moon.pkg` 与旧 `moon.pkg.json` 均可提供包导入提示。

[三套 2026 工具链 × 四后端矩阵](docs/metrics/native-version-matrix-2026-09-25.json)通过便携语法的选源和规则对照，但不代表完整语言支持。真实 2025 QuickCheck 项目在对应 moon `0.1.20251030` / moonc `v0.6.30` 下可编译；30 个文件选择一致，初次实验 parser 仅解析 **16 个，14 个失败**，扫描返回 `scope_incomplete` / **2**。后续有限兼容补丁已提升至 22/30（见上方前端对照）。这是旧工具链接入的通过证据，也是旧语法覆盖不完整的证据，不能承诺任意老项目兼容。[历史项目验收](experiments/historical_project/README.md)

已知新语法 `for (x, y) in ...` 也存在编译器接受而 parser `0.4.0` 拒绝的差异。工具保留已解析文件的发现和明确错误，不把部分 AST 或零告警当成全项目完成。

## 开发验证与后续方向

```bash
moon test --target all --deny-warn
moon fmt --check
moon info
python3 scripts/cli_regression_test.py
python3 experiments/rule_audit/validate_registry.py \
  --analyzer _build/native/debug/build/src/main/main.exe --output /tmp/rules.json
moon build --target native --release
python3 scripts/package_native.py --platform linux-x86_64 --output dist
ANALYZER="$PWD/dist/extracted/moon-audit" PROJECT_TOOLCHAIN=/path/to/moon \
  python3 scripts/native_delivery_test.py
ANALYZER="$PWD/dist/extracted/moon-audit" python3 scripts/process_supervision_test.py
```

这些 Python 是开发验收工具，分发包运行不依赖 Python。旧 [Python IR 规格](experiments/core_semantics/README.md)和 [前端原型](experiments/frontend_adapter/README.md)保留为研究对照，不能算生产通用堆/别名能力。旧反例保留原预期。

本阶段 A–D 的有限实现及三平台交付验收已完成；审查分支和 draft PR 已准备好，合并与正式发行由维护者决定。下一阶段才考虑历史语法适配、更多真实模型、控制流和堆；不以复制 Tai-e 的广度为目标。

[TODO 与里程碑](TODO.md) · [架构方案](docs/architecture-plan-2026-09-24.md) · [当前建议](suggest.md) · [基础设施调研](docs/moonbit-infrastructure-research-2026-09-22.md)

删减前工作区保存在被 Git 忽略的本机 `.recovery/2026-09-22-before-redesign`；[归档 README](docs/legacy/README-before-redesign.md)不代表当前能力。

### 受限程序排除实验

可选离线助手 `scripts/verify_counterevidence.py`（二进制包的 `extras/`）验证三类程序排除：不可变 Bool 分支矛盾、闭式无载荷枚举的“提前 return + 后续覆盖”fallback，以及无条件 raise 前驱。配置预检分两路：简单 legacy JSON 项目走严格本地 JSON 门禁；更丰富或现代（`moon.mod`/`moon.pkg`）配置经分析器 `--internal-counterevidence-config` 用官方 `moon_config` 解析器结构化校验（本模块/core 导入、`pkgtype {kind}`，拒绝钩子、外部依赖和 stub 依赖闭包；本地模块名不获 pinned-core 信任）。当前仅限固定 Linux/native 工具链；普通扫描支持范围不变。模型的 FP 意见没有过滤权限，新助手保留原始 findings 和全部候选；项目覆盖不完整时保留 `scope_incomplete`，只给局部证明。2026-09-28 新增第三类程序排除（`verified_unconditional_raise_predecessor`）：sink 的直接顺序前驱是对唯一声明的调用，且该声明体恰为 `raise 构造器(简单载荷)`、异常构造器/载荷/前后驱 callee 绑定与唯一生产单位全部核实时，仅证明该后继 sink 不可达；变异（保留 `raise` 签名但正常返回）使证明消失且运行时在原行 SIGABRT。原30条中 BioSeqs case-014 首次获得程序证据（冻结30条中可信排除 0→1）。[raise 反证实验](experiments/raise_counterevidence/acceptance.py)。具体使用与已知限制见[LLM 复核文档](docs/llm-review.md#程序排除门槛实验功能)；Bool 正反例见[验收记录](experiments/local_counterevidence/README.md)，真实 x 0.5.5 枚举位点及危险变异见[枚举实验](experiments/enum_counterevidence/README.md)。
