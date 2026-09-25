# 2025 真实项目与文件范围验收

后续已完成旧 `try?`/`loop` 的有限前端适配，见[最新对照](../frontend_compat/README.md)。下文保留原始实验结果，不改写历史统计。

本实验固定未迁移源码的官方 QuickCheck 项目，验证旧编译器能否检查、其真实文件计划能否接入，以及当前扫描器是否诚实报告不支持的旧语法。它不把“编译检查通过”解释为“旧源码已完整扫描”。

## 固定输入与来源

- 项目：[moonbitlang/quickcheck](https://github.com/moonbitlang/quickcheck/tree/04e4d54c0b3cb5a53f2c2530f7eadf546a903f60)，提交 `04e4d54c0b3cb5a53f2c2530f7eadf546a903f60`，2025-10-31，模块版本 0.9.9，无外部依赖。
- 工具链：`moon 0.1.20251030 (cf54fca)`、`moonc v0.6.30+07d9d2445`，配套同版本 core。
- 旧官方下载端点本次返回 HTTP 403；使用 [chawyehsu/moonbit-binaries 固定历史发布](https://github.com/chawyehsu/moonbit-binaries/releases/tag/v0.6.30%2B07d9d2445)，不声称本次从官方旧端点成功下载。工具链及 core SHA-256 对照 GitHub 发布资产 digest；Linux 工具链散列也与 [社区版本索引](https://github.com/moonbit-community/moonbit-overlay/blob/master/versions/toolchains/v0.6.30%2B07d9d2445.json) 一致。
- 下载 URL、归档 SHA-256、被检查的 55 个原始文件 SHA-256、分析器 SHA-256 和逐文件结果见 [指标](../../docs/metrics/historical-project-2026-09-25.json)。源码和依赖声明未修改；构建仅在 `/tmp` 生成缓存。

## 结果

2026-09-25 在 Linux x86_64 实测：

| 步骤 | 结果 |
| --- | --- |
| 旧工具链 `moon check --frozen --target native` | exit 0 |
| 旧工具链原始 dry-run 计划 | exit 0，30 个源码文件 |
| 归档源码、独立计划解析、原生报告逐文件对照 | 30 个文件完全一致 |
| 基础语法扫描 | 30 selected、16 parsed、14 parse_failed，exit 2 |
| 原生 `--verify-project` | 同上，`scope_incomplete`，exit 2 |
| PATH 只有旧工具链 bin，无 Node | 同样到达 `scope_incomplete`，不再被可选 moon-pilot 身份查询阻塞 |
| 未修改原始内容 | 归档内 55 个文件逐字节 SHA-256 一致 |

`loop`、`typealias` 等历史语法被当前打包 parser 拒绝。零发现只覆盖成功解析文件上实际启用的规则；不是整个历史项目的安全结论。这个样本证明旧工具链接入和不完整报告可用，**不证明当前 parser 已支持该版本全部语法，更不证明任意老项目兼容**。增加解析器版本适配之前，应把该项目列为“编译器可验证、扫描范围不完整”。

### 两代真实工具链的 8 项范围反例

每代分别检查 4 项，并独立对照原始编译器计划，不使用假 moon 输出：

| 反例 | 2025 工具链 | 2026 固定工具链 |
| --- | --- | --- |
| 包 `supported-targets: [js]`，检测 native | 旧工具忽略该字段，计划/扫描均 2 文件 | 新工具排除该包，计划/扫描均 1 文件 |
| `_test.mbt`、`_wbtest.mbt` | 计划 3，扫描 1，`policy_excluded_files` 明确列出 2 | 相同 |
| 扫描配置排除一个包 | 计划 2，扫描 1，明确列出 1 个策略排除文件 | 相同 |
| 无源码的包 | 编译检查成功；0 文件，`scope_incomplete`，exit 2 | 相同 |

前三项保持 `compiler_verified` 只表示声明策略范围内已核实；测试文件与配置排除不是已检查内容。旧工具链会忽略新元数据这一差异也说明：必须按实际工具链打印的计划选择文件，不能自行把新版配置语义套到旧版项目。

## 重现

需要 Linux x86_64、开发测试用 Python 3.12、已构建原生分析器，以及已安装且已 bundle core 的当前固定工具链。`--download` 只获取脚本内固定 URL；所有归档必须匹配固定 SHA-256，不运行下载的 shell 安装器。生产工具运行不需要 Python。

```sh
python3 experiments/historical_project/verify.py \
  --work-dir /tmp/moon-audit-historical-2025 \
  --analyzer _build/native/debug/build/src/main/main.exe \
  --scope-toolchain /tmp/moon-audit-upgrade-20260922/toolchain \
  --output /tmp/moon-audit-historical-2025/evidence \
  --download
```

脚本会验证原始归档的全部文件未被修改、隔离复制待测分析器、执行旧 core bundle 与项目检查，保存完整 stdout/stderr 和 `metrics.json`，最后对两代工具链的 8 个范围反例逐项断言。已有归档时可省略 `--download`；修改源码或归档散列不匹配会直接失败。

## 本轮顺带修复的交付阻塞

1. `moon 0.1.20260920` 是构建工具身份，不是编译器归档版本。当前固定下载 ID 应为 `0.10.14+7d59c7ec9`。三平台精确 URL 和 SHA 见 [toolchain-downloads.json](toolchain-downloads.json)。其中平台 SHA 来自官方 checksum 端点，core 已完整下载计算；不把这些端点可获取等同三平台产物已通过运行验收。
2. 旧 `moon version --all` 会调用需要 Node 的可选 moon-pilot。原生入口现允许在这个查询失败时改查 `moon version` 与同工具链 `moonc -v`；无 Node 复验通过。编译器查询本身失败仍不能宣称已核实。

本实验仅有 Linux 执行证据；macOS/Windows 仍需各自真实 CI。完整 stdout/stderr 可用以上命令重建，关键原始文件计划已留在 [evidence](evidence/) 中。
