# moon-audit

面向下载源码自行编译、或下载原生二进制的用户，检测自己的 MoonBit 项目和第三方源码。当前为 **0.5.0-dev**：默认提供有限语法扫描，另有**显式限定范围的可选安全数据流分析**。零发现不等于项目安全；报告同时给出发现、证据和未分析范围。

## 当前能做什么

| 模式 | 已实现能力 | 边界 |
| --- | --- | --- |
| 默认 `syntax` | 14 条语法提示规则、文本/JSON/SARIF、baseline、文件列表扫描 | 仅默认启用 `CWE-116/replace-escaping`、`CWE-79/cmark-unsafe`；其余显式选择。全部为 `syntax_hint`，不证明 API 身份或漏洞 |
| `--verify-project` | 用项目自己的工具链编译检查、按后端文件计划选源、核对源码和依赖快照 | 编译通过不代表分析器能解析全部语法；不自动安装或升级项目依赖 |
| 可选 `semantic` | 固定 mocket 查询参数→String helper→最终返回 HTML responder；复用同一 IR 接入固定 cmark 渲染模型 | 仅 native、声明的 `mocket-get-callbacks` 范围与核实的模型指纹；不证明注册可达性、中间件行为或浏览器可利用性 |

规则默认策略、分发和报告能力由同一登记生成。`--rule` 可选择其余规则，但不会把名称匹配升级为真实绑定。逐条依据见 [14 条规则审计](experiments/rule_audit/README.md)。旧 CFG/污点 DSL/LLM/pipeline 入口已移除；旧选项和配置会被拒绝。

前端使用固定官方 parser 0.4.0 加窄范围兼容补丁，已支持旧 `try?`、`loop` 的语法扫描；报告显示 `0.4.0+moon-audit-legacy.1`。未建模的旧构造在语义模式仍报不完整。[真实新版/2025 项目对照与边界](experiments/frontend_compat/README.md)

普通目录扫描识别 `.mbt`、`.mbt.md`、`.mbtx` 输入；目前仅解析 `.mbt`，其余逐文件记录为 `unsupported` 并返回 2，已有发现保留。增量列表、排除策略和已识别的编译计划同样约束这些输入。嵌套模块以各自最近的 `moon.mod` / `moon.mod.json` 判断模块身份，止于扫描根；包导入仍只取本包配置。这不等于自动编译整个工作区。[输入契约与复测](experiments/project_inputs/README.md)

## 本地使用与构建

用户运行原生二进制无需 Python。默认源码扫描也无需目标项目工具链；项目验证和语义模式需要项目工具链及已准备的依赖。

```bash
moon-audit --format json /path/to/project
moon-audit --rule CWE-113/crlf-injection /path/to/project
moon-audit --verify-project --project-toolchain /path/to/project-moon \
  --target native --format sarif -o results.sarif /path/to/project
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
