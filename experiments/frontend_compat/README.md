# 旧语法兼容前端验收（2026-09-25）

本轮在固定官方 parser 0.4.0 上，回移官方 0.3.0 的旧 `loop` 和 `try?` 表示与 Handrolled 产生式。兼容标识为 `0.4.0+moon-audit-legacy.1`；保留原始节点、位置、标签和优先级，不改写用户源码，也不新增它们的数据流语义。

## 真实源码结果

| 固定样本 | 修复前解析/选择 | 本轮解析/选择 | 本轮结论 |
| --- | --- | --- | --- |
| QuickCheck 0.14.0 | 30/34 | 34/34 | 完成声明的语法扫描范围 |
| bitflow 0.4.1 | 11/12 | 12/12 | 完成声明的语法扫描范围 |
| QuickCheck 2025-10-31、0.9.9 | 16/30 | 22/30 | 仍有 8 个文件解析失败，scope_incomplete / exit 2 |
| core 固定 5992620 | 478/478 | 478/478 | 目录扫描结果保持一致 |
| actrun 固定 1db9aff | 62/62 | 62/62 | 目录扫描结果保持一致 |

前两项及 core/actrun 沿用[热门项目原清单](../popular_projects/manifest-2026-09-25.json)。它们的源码指纹前后不变；581 个此前官方 Handrolled 可接受文件的 AST（包含位置）逐一相等，新增解析 5 个文件。此前已解析文件的全部规则发现保持一致：QuickCheck、bitflow、core、actrun 分别为 1、0、0、33 条语法线索。不是已验证漏洞或准确率统计。

- [QuickCheck/bitflow 完整摘要与逐文件 AST 对照](results-2026-09-25/summary.json)，同目录保存修复前后压缩 JSON。
- [core/actrun 对照](current-syntax-2026-09-25/summary.json)。这里是普通目录扫描的 478/62；不替代上轮 native 编译计划下的 449/56，也不解除 `.mbt.md` 缺口。
- [2025 旧工具链复测](historical-2025/metrics.json)：对应 moon 0.1.20251030 / moonc v0.6.30+07d9d2445；55 个归档文件逐字节不变，旧编译器计划仍为相同 30 个源码。常规 PATH 与仅含旧工具链的 PATH 都为 22 parsed / 8 failed，两代工具链的 8 个选源反例通过。原先 16/30 的记录保留在[历史实验](../historical_project/README.md)。这不证明任意 2025 项目兼容。

## 错误不能被回退清除

补充检查发现官方入口会忽略 lexer 的错误数组：恢复出的 AST 可能被错误当成完整解析。现在两个解析器入口均保留词法错误及其原始位置；共享前端回退不能把错误清零。插值重新词法分析显式传入原文件名，行列和文件身份一起保留；新增非法插值反例验证该边界。

[三个编译器对照反例](lexical-rejection-2026-09-25.json)包含旧 loop、try? 和普通表达式后混入非法字符。词法保护修复前扫描器返回 0、编译器 syncheck 返回 2；修复后扫描器同样返回 2。该记录的 before 是本轮已支持旧语法但尚未加词法保护的中间二进制，不是 main 基线。

## 语法支持与安全语义分开验收

规则扫描、插值展开、原生语义入口共用同一兼容 AST。`Loop` 与 `TryOperatorKind::Question` 没有被映射成现代 for/try!：语义降低分别报 `unsupported_legacy_loop`、`unsupported_legacy_try_question`。真实 mocket 反例先通过编译和解析，再确认 semantic exit 2、语法线索仍保留、没有生成 verified_dataflow。

[最终 Linux 生产入口 16 项验收](semantic-acceptance-2026-09-25.json)包含上述拒绝边界及此前 cold/hot、baseline、预算、模型变化和子进程故障保护。

## 可维护性与范围

- [来源锁与完整补丁](../../src/vendor/parser_compat/README.md)固定 28 个上游文件及两个官方归档。原生用户编译无需 Python 或 parser generator；Python 只用于开发验收和原有可选 LLM 助手。
- 实际补丁 486 行（含上下文、包路径/格式配置、词法错误保留）；约 2.7 MB 是复用的上游前端源码，大部分是未修改的生成 yacc 表。构建时不再生成该表，CI 检查逐文件哈希与补丁一致性。
- MoonYacc 仍是未增加旧语法的当前语法回退；不能推断所有混合语法都已支持。原始 registry parser 保留为独立 AST 对照工具的默认入口。
- 其他旧语法、tuple-pattern `for ... in`、`.mbt.md`/`.mbtx`、未建模异常和循环数据流仍不在已完成范围。
- 下一步优先制定 `.mbt.md` 的代码块、位置和展示/编译范围契约，再做有限输入适配；[官方文档](https://docs.moonbitlang.com/en/latest/language/docs.html)区分不同 fence 的编译行为，必须用固定版本编译器对照，不能把所有展示代码都算作已检测。

## 验收与重跑

本地最终结果：wasm/wasm-gc/js 各 86 项，native 88 项；解包交付 30 项、CLI 22 项、进程监督 4 项、生产语义 16 项通过。新增词法/节点测试包含非法输入、主/回退解析器、位置、标签、优先级、插值和规则访客。最终三平台 CI 与独立复核以审查 PR 的记录为准。

```sh
python scripts/check_frontend_vendor.py --upstream .mooncakes/moonbitlang/parser
python experiments/frontend_compat/compare_projects.py \
  --before /path/to/baseline/moon-audit --after /path/to/current/moon-audit \
  --exporter _build/native/release/build/src/frontend_export/frontend_export.exe \
  --source-root /path/to/pinned-popular-sources --output-dir /tmp/frontend-comparison
```

该驱动验证固定源码指纹、已解析文件告警不变和官方/兼容 AST 一致；不运行目标项目的应用程序。可用重复的 `--project` 参数选择原清单中的 core、actrun 等项目。
