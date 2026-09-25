# 受限 MoonBit 前端适配实验

这是与生产模式扫描器隔离的源码到 IR 实验。`src/frontend_export` 使用固定版本的官方 parser 导出带源码位置的 AST；`adapter.py` 先让目标项目选定的 moonc 编译测试项目，再用 `moon ide peek-def` 对每个受支持的直接调用核实声明位置，最后把 AST 降低到 `experiments/core_semantics` 的顺序 IR。核心只读取 IR，不读取旧扫描器结果。

## 当前受支持范围

目前有两个明确分开的源码子集：① 单文件 `Box` 字段实验，允许显式 `String`/`Box` 形参、`Unit` 返回、普通直接调用、按值局部绑定及遮蔽、String 常量、完整结构体初始化和顺序字段读写；② **无堆 String 流实验**，不声明 `Box`，允许显式 `String` 形参、`String`/`Unit` 返回和普通直接调用。两者都按 AST 顺序求值实参，并在调用后进入新基本块；Box 与 String 返回的组合暂时明确拒绝。`source()` / `sink(value)` 是实验明确配置的两个测试模型，适配器验证其声明身份、原型和函数体指定形态；**仍没有真实 CWE-113 API 模型**。

分析器构建侧固定为 moon `0.1.20260920`、moonc `v0.10.14+7d59c7ec9`、parser `0.4.0`、native；**目标项目不被锁到该版本**。目标项目使用选定的自身 `moon` 执行 `check` 和 `peek-def`。已分别验证目标 moon `0.1.20260904` / moonc `0.10.12`、moon `0.1.20260915` / moonc `0.10.13`、moon `0.1.20260920` / moonc `0.10.14`。`go` 是无参数入口。任何其他表达式、泛型、间接调用、方法、异常、分支、闭包都返回明确拒绝状态；仅分析器构建侧版本或 parser 依赖不匹配才拒绝；没有旧 AST 摘要或“猜测安全”的回退。求解器预算用尽时仍由独立核心返回 `incomplete_budget`。

## 复现

分析器与目标项目可使用不同工具链。默认两侧都用 `PATH` 中的 `moon`；下面是分析器侧由固定版本 wrapper 启动、项目侧显式指定另一版本的例子：

```bash
ANALYZER_MOON_WRAPPER=/path/to/analyzer-wrapper \
PROJECT_MOON_WRAPPER=/path/to/project-wrapper \
python3 -m unittest discover -s experiments/frontend_adapter -p 'test_adapter.py' -v
python3 experiments/frontend_adapter/validate.py \
  --analyzer-moon-wrapper /path/to/analyzer-wrapper \
  --project-moon-wrapper /path/to/project-wrapper \
  --baseline docs/metrics/frontend-adapter-2026-09-24.json \
  --output /tmp/frontend-adapter-validation.json
python3 experiments/frontend_adapter/adapter.py \
  experiments/frontend_adapter/fixtures/read_after_write_alias.mbt.txt \
  --analyzer-moon-wrapper /path/to/analyzer-wrapper \
  --project-moon-wrapper /path/to/project-wrapper \
  --output /tmp/frontend-adapter-example.json
```

wrapper 应设置对应的 `MOON_HOME` 和 `PATH` 后执行传入命令。`--analyzer-moon-wrapper` 用于构建 AST 导出器，`--project-moon-wrapper` 用于编译/查询目标项目；两者可不同。目标版本不在代码里逐个白名单放行，而是必须通过真实编译、唯一声明绑定、受支持 AST 结构和语义结果检查。此处的七组通过并不意味着生产扫描器能解析该版本的所有语法；[正式扫描器的跨版本矩阵](../version_compat/README.md)另有合法新语法的解析缺口。示例报告有 `status`、已核实的调用位置、AST 结构清单、IR 和核心发现。七组源码对照的机器记录在 `docs/metrics/frontend-adapter-2026-09-24.json`。

## 官方语法升级步骤

官方 [parser README](https://github.com/moonbitlang/parser) 标注该模块实验性且不稳定，因此把版本、AST 结构和语义结果分开验收：

1. 区分分析器构建工具链与目标项目工具链。CI 的 `frontend-contract` 在同一个分析器版本下分别检查三个目标版本；原有 CI 工作继续跟随官方最新工具链，作为升级信号。不要把 `moon.mod` 的 `version` 当作编译器版本，它是模块自身版本。
2. 在隔离分支升级 moon、moonc、parser/lexer。先运行 `moon check --target all --deny-warn`、`moon fmt --check` 和原扫描器测试，再运行本目录的真实源码单测。
3. 升级分析器自身的 parser/编译器时，先审查 AST 和 IDE 响应，再调整 `adapter.py` 的分析器版本常量；分析器侧不匹配返回 `analyzer_toolchain_mismatch` 或 `parser_dependency_mismatch`。目标项目用其选定的编译器直接验证，不设补丁版本白名单；目标源码编译失败返回 `compiler_rejected`。
4. 用 `validate.py --baseline <旧机器记录> --output <新记录>` 比较每个样例的 AST 节点结构和告警布尔结果。结构或结果变化会产生 `baseline_differences` 并退出失败；确认差异原因、补足合法语法与拒绝样例后，再更新基线。只变行列号、注释或空白时按语义结果比较，不靠完整 AST 字节相等。
5. 新语法即使被编译器接受，若本适配器不能忠实降低，应返回 `parser_rejected` 或 `unsupported_syntax/unsupported_semantics`。若官方 IDE 不再提供唯一声明，返回 `binding_unavailable`。不要自动切换到旧扫描器或用短名称假定调用目标。

目前三个目标编译器版本各有七组源码对照通过，其中新增两组无堆 String 参数/返回正反例。范围仍限于小子集；没有覆盖 MoonBit 全语法、跨包、多态派发、异常、递归源码或真实项目成本。官方语法更迭时按语法特征补样例和前端适配，不为每个补丁版本复制一套完整求解器。
