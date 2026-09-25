# moon-audit

面向项目开发者和第三方源码审计者的本地 MoonBit 安全检测工具。当前开发版本为 **0.5.0-dev**，生产能力仍为语法模式扫描；真实数据流核心正在独立验证。

当前保留 14 条模式规则、官方 parser、文本/JSON/SARIF 报告、baseline 和文件列表扫描。**不提供类型解析、跨函数污点、字段别名或净化效果证明。** 零告警不表示项目安全；报告始终披露分析范围。

CWE-113 当前只对动态头部值提供低置信度人工复核提示。与旧版相比，CFG/调用图/污点 DSL/LLM/pipeline 等入口已移除；请求旧引擎选项或污点配置会报错。

## 本地使用与原生构建

原生入口无需 Python。源码模式无需安装目标项目工具链；显式项目验证需要项目自身的 MoonBit 工具链和已安装依赖。当前 Linux x86_64 已完成本地归档验收；macOS arm64、Windows x86_64 的交付工作流已加入，须以对应原生 runner 的实际结果为准，尚未据此宣称发布。

```bash
# 解包后的单个可执行文件；Windows 使用 moon-audit.exe
moon-audit --format json /path/to/project
moon-audit --verify-project --project-toolchain /path/to/project-moon \
  --target native --format sarif -o results.sarif /path/to/project
moon-audit list-rules
```

`--project-toolchain` 指向包含 `bin/moon` 或 `bin/moon.exe` 的工具链根目录。也可用互斥的 `--project-moon /path/to/moon` 指定可执行文件，此时保留调用者环境；两者都未指定时从 PATH 查找。工具链选项须和 `--verify-project` 一起使用。工具按参数数组调用，不接受 shell 命令字符串。

源码构建固定 moon `0.1.20260920` / moonc `v0.10.14`；需要本机 C 编译器。分析器的构建版本独立于目标项目版本，依赖版本见 [moon.mod](moon.mod)。

```bash
moon update
moon check --target all --deny-warn
moon build --target native --release
# 产物：_build/native/release/build/src/main/main.exe
# 也可在开发环境使用：
moon run src/main -- --format json /path/to/project
```

保留 `--format`、`--output`、`--config`、`--severity`、可重复 `--rule`、`--changed-files`、`--baseline`、`--fail-on-error`、`--verbose`、`--quiet`。`--analysis syntax` 为默认；`--analysis semantic` 尚未通过生产接入验收，明确拒绝。增量文件列表不分析受影响调用者，空列表主动检查零文件。

```bash
moon-audit generate-baseline -o baseline.json /path/to/project
moon-audit --baseline baseline.json /path/to/project
moon-audit generate-baseline --verify-project \
  --project-toolchain /path/to/project-moon -o baseline.json /path/to/project
```

退出码：`0` 表示所请求检查结束且未触发告警退出策略；`--fail-on-error` 遇到 Error 级发现返回 `1`；参数、读取、解析、项目验证或报告写入失败返回 `2`。baseline 不会隐藏验证失败，验证或解析失败不会更新 baseline。源码模式的明确能力边界不会使其恒定返回 `2`。零文件和零发现不表示项目安全。

显式验证执行 `moon check --frozen` 和同一工具链的文件计划，不自动安装或升级依赖，可能写入项目构建缓存。失败时保留可获得的源码发现，并标记验证失败；成功时仅扫描该后端计划内符合选择策略的文件。

`--timeout-seconds` 默认 300，作用于每次外部命令；不代表整个项目的总预算。双流捕获各限 16 MiB，超限或超时终止受监督的进程树。快照最多 100000 个相关文件、单文件 16 MiB、累计 256 MiB、遍历检查 30 秒；链接/特殊路径无法核实时显式返回不完整。扫描前后源码、包配置或依赖快照变化同样使验证失效。

JSON 顶层和 SARIF run properties 的 `project_verification` 记录工具链、后端、编译文件、排除/缺失文件及 SHA-256 快照。源码模式该字段为 null。`compiler_verified` 只证明编译、文件选择和解析范围，不证明规则绑定或漏洞。默认文本提供摘要，`--verbose` 才展开快照。

## 不同 MoonBit 版本的项目

扫描器可以独立于目标项目的工具链运行；它使用打包的 parser 解析目标源码。若需确认该源码在项目自己的 MoonBit 版本下有效，使用上述原生 `--verify-project` 入口（[Python 开发对照](experiments/version_compat/README.md)仍保留）：指定项目工具链后先编译，再读取该工具链的后端文件计划，只扫描实际选中的 `.mbt` 文件，并报告编译器身份、文件差异、解析错误及扫描状态。普通 CLI 不按后端过滤文件。

目前目标 moon `0.1.20260904`、`0.1.20260915`、`0.1.20260920` 已通过一组便携语法的真实编译与 CWE-116 点调用、显式调用正负对照；这只证明该子集。先前漏报的等价调用 `String::replace(s, ...)` 已在这三个版本的真实编译与扫描中修复；但 `compiled_and_parsed` 仍只说明编译和解析完成，不代表全部规则的语义覆盖。三个编译器都接受的 `for (x, y) in ...`，打包的 parser `0.4.0` 仍会拒绝，严格入口返回 `scope_incomplete`。发现这种差异时，报告保留已分析文件的发现，但不能解释为整个项目已检测完成。完整[版本矩阵与缺口](docs/metrics/project-version-compat-2026-09-24.json)可复核。

JSON/SARIF 另报告 `files_selected`（排除与增量过滤后选中）、`files_parsed`（解析成功并执行规则）计数。旧 `files_scanned` 保留已读取且尝试解析的兼容含义；解析失败文件不会计入 `files_parsed`。规则语义覆盖仍需单独验证。

JSON 的 `analysis_manifest`（SARIF 位于 `runs[0].properties.analysis_manifest`）以 `moon-audit.analysis-manifest.v1` 记录候选文件的 `parsed`、`parse_failed`、`read_failed` 或增量 `skipped` 状态，并列出已解析文件上 14 条规则的 `evaluated`、`disabled` 或 `gated_out` 状态。`evaluated` 只表示语法规则已运行，发现的 `evidence` 始终是 `syntax_hint`；`gated_out` 依据包导入提示，不是已验证的 API 身份。新 `moon.pkg` 和旧 `moon.pkg.json` 均可提供包导入提示；模块依赖本身不会替包启用规则，损坏的旧包配置会使扫描返回错误。`selection` 说明默认与配置排除：被排除的目录和测试文件不会逐一枚举。普通入口未核实目标工具链与后端实际编译文件，`incomplete_reasons` 会保留这两个缺口；零发现不能解释为完整安全结论。`analysis_scope` 和旧计数字段继续保留。

## 验证

```bash
moon test --target all --deny-warn
moon fmt --check
moon info
python3 scripts/cli_regression_test.py
python3 -m unittest experiments.core_semantics.test_engine -v
```

CLI 回归需要先生成 `_build/native/debug/build/src/main/main.exe`。最后一项验证独立 Python IR 规格，不能作为生产跨函数能力的证明。另有 [受限源码到 IR 实验](experiments/frontend_adapter/README.md)，在固定分析器工具链与三套目标编译器下验证 Box 字段顺序及无堆 String 直接调用/返回；它尚未接入生产 CLI。`tests/cases` 和 `docs/review-fixtures` 保留旧语义反例及原预期，当前有限扫描器不承诺通过它们。

## 重设计方向

1. 先完善有限扫描器的文件、规则和项目版本覆盖报告，并保持语法提示的证据等级。
2. 为一条真实安全链固定可编译的库/API、工具链与后端，验证声明绑定、危险输出和安全负例；当前 mocket 查询参数到 HTML 返回值的受限链已完成运行、绑定和原生 IR 实验；CWE-113 不作为首条链。
3. 仅在真实 API 验证通过后，从受限源码生成顺序 IR，在独立核心中验收正反例和成本，再决定该规则是否接入生产入口。

[当前 TODO 与里程碑](TODO.md) · [当前架构方案](docs/architecture-plan-2026-09-24.md) · [Tai-e 核心取舍与基础设施调研](docs/moonbit-infrastructure-research-2026-09-22.md) · [精简落地与重设计方案](docs/redesign-2026-09-22.md) · [当前建议](suggest.md)

删减前工作区已保存在 `.recovery/2026-09-22-before-redesign`，这是被 Git 忽略的本机恢复点。历史功能说明见 [归档 README](docs/legacy/README-before-redesign.md)，不代表当前支持能力。

## 原生交付验收

```bash
moon build --target native --release
python3 scripts/package_native.py --platform linux-x86_64 --output dist
ANALYZER="$PWD/dist/extracted/moon-audit" PROJECT_TOOLCHAIN=/path/to/moon \
  python3 scripts/native_delivery_test.py
ANALYZER="$PWD/dist/extracted/moon-audit" python3 scripts/process_supervision_test.py
```

打包和验收脚本属于开发工具，分发包运行不依赖 Python。三平台归档由 `native-delivery` 工作流分别构建和测试。固定项目的运行和声明绑定证据见 [mocket 首条真实安全链](experiments/security_chain/README.md)：这些实验已包含真实源码到原生 IR 的 13 项正反例验收；仅覆盖固定库的受限回调返回值，不代表生产语义检测已经完成。
