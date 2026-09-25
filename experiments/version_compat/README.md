# MoonBit 项目版本兼容性验证

目标是让**同一个 moon-audit 扫描器**检测由不同 MoonBit 工具链编译的项目。分析器的构建版本和被检测项目的编译器版本是两个独立输入。`moon.mod` 的 `version` 表示模块发布版本，[官方模块配置文档](https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html#version)并没有把它定义为编译器版本，因此不能从该字段选择语法适配器。

## 严格扫描入口

项目自己的工具链已安装时，从仓库根目录运行：

```bash
python3 scripts/scan_compatible.py /path/to/project \
  --project-moon-wrapper /path/to/project-toolchain-wrapper \
  --scanner /path/to/moon-audit-binary \
  --output /tmp/scan-result.json
```

wrapper 设置 `MOON_HOME` 与 `PATH`，然后执行收到的命令。省略它则使用当前 `PATH` 中的 `moon`。脚本先获取 `moon version --all` 并用该工具链执行 `moon check --target native`；编译通过后读取同一工具链的 `moon check --dry-run --verbose` 计划，提取实际参与该后端检查的 `.mbt` 文件，并用 `--changed-files` 交给现有扫描器。仅当**编译通过、计划可读取、计划内符合扫描器选择策略的文件均被 parser 接受、无扫描错误或文件差异**时，状态为 `compiled_and_parsed`。此状态仍只证明选中源码的编译与语法通过，不证明规则语义或 API 绑定。

外层报告 schema 是 `moon-audit.compatible-scan.v2`，`file_selection` 列出编译器文件、扫描器按既有策略排除的文件、未支持的编译器文件格式、实际解析文件与差异。计划无法读取返回 `compiler_plan_unavailable`；没有选中任何项目 `.mbt`、文件差异或 `.mbt.md`/`.mbtx` 等未支持格式返回 `scope_incomplete`；解析错误返回 `scanner_incomplete`，均退出 2。扫描器嵌入的 `analysis_manifest` 仍是原始语法扫描报告，其目标工具链字段保持“未在扫描器内核实”；外层记录本次严格验证。`moon check` 可能写入项目构建缓存。需要其他后端时传 `--target js|wasm|wasm-gc`。

原 `moon-audit` CLI 仍可直接扫描项目；它不需要目标项目工具链，但只记录分析器的 parser 版本，不能据此推断项目的编译器版本或后端文件集合。需要核实源码在指定 MoonBit 版本下是否有效时，使用上述严格入口。

## 已验证范围与真实缺口

[机器矩阵](../../docs/metrics/project-version-compat-2026-09-24.json)记录目标 moon `0.1.20260904` / moonc `0.10.12`、moon `0.1.20260915` / moonc `0.10.13`、moon `0.1.20260920` / moonc `0.10.14`。分析器统一由 moon `0.1.20260920` 和 parser `0.4.0` 构建。

每个目标版本都通过：四份真实编译的源码分别验证点调用和显式调用的 CWE-116 正反例；独立前端的七组字段/别名与无堆 String 对照结果相同。模块版本在测试中故意写作 `9.9.9`，证明判断依据是实际 `moon version`，不是模块元数据。

此前发现的**显式调用漏报已关闭**：三个编译器都能编译、运行 `s.replace(...)` 与 `String::replace(s, ...)`，测试确认样例结果相同；当前扫描器对两处均报告 CWE-116，`String::replace_all` 和非危险替换保持无告警。矩阵的 `equivalent_call_shape.status` 现为 `supported`。这只验证该规则的这两种调用形式；`compiled_and_parsed` 仍不等于所有规则都已验证。

同时存在一个**已验证解析缺口**：三个编译器均接受 `for (x, y) in ...` 模式解构，但 parser `0.4.0` 会在 `(` 处报错。严格入口对此返回 `scanner_incomplete`，不会给出“无问题”的结论。[官方 0.10.14 发布说明](https://www.moonbitlang.com/updates/2026/09/21/index)也列出了 `for...in` 模式匹配。此缺口不能靠放宽版本号或仅增加 CI 行解决；需要能解析该结构的官方前端，或经过独立语义验证的适配层，且必须保持源码位置和规则访问顺序。

CI 的 `frontend-contract` 对三个目标工具链逐一执行编译、扫描和 AST/语义基线对照。新增版本应先加入版本矩阵并记录选中文件解析率、规则正负例、等价调用形状和未支持语法；只给一个版本号贴“支持”标签不够。当前生产扫描器只对 **14 条规则中的 1 条**完成跨版本真编译对照，独立核心仅覆盖受限 `Box` 子集；还不能宣称全规则或任意版本兼容。

已检查同包的官方 `untyped_cst.parse_structure(...).to_impls()`：对上述模式仍产生解析诊断，不能作为透明回退。旧本地官方 `tree-sitter-moonbit` 语法的 `for_in_expression` 也只接收小写标识符列表，而且 tree-sitter 不提供编译器类型/绑定事实；它可作为未来的语法候选，但不能凭名称直接替换现有前端。

## 2026-09-25 范围门禁验收

旧格式 `moon.pkg.json` 的数组字符串、`{path, alias}` 数组项及路径到别名的对象映射均已进入包导入门禁；损坏的旧包 JSON 会使普通扫描返回错误，而不是静默关掉相应规则。`moon.mod.json` 可提供模块身份，但模块依赖不会当作每个包的导入。这个约束依据[官方包配置说明](https://docs.moonbitlang.com/en/latest/toolchain/moon/package.html#import)中的包级 `import`；同一文档的 [`targets`](https://docs.moonbitlang.com/en/latest/toolchain/moon/package.html#conditional-compilation)说明了按文件切换后端。

[真实编译探针及工具链记录](../../docs/metrics/legacy-backend-scope-2026-09-25.json)使用旧 `moon.mod.json`/`moon.pkg.json`，并将 `js_only.mbt` 与 `native_only.mbt` 分配给不同后端。目标 moon `0.1.20260904`、`0.1.20260915`、`0.1.20260920` 的 native 文件计划均只包含公共文件与 native 文件；`0.1.20260920` 的 JS 计划只包含公共文件与 JS 文件。后端限定的 CWE-116 提示只在 JS 严格扫描中出现。此结论只覆盖这三个固定工具链和简单 `targets` 样例；遇到其他版本的计划格式变化，严格入口应返回 `compiler_plan_unavailable`，不猜测文件集合。
