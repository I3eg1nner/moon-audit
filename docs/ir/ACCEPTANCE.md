# 验收体系（Acceptance System）

> 对应外部评审第 4 部分：TP/FP/FN 口径、缓存失效、动态真值、性能口径。
> 本文件是验收的**契约文档**；实现落点：`src/acceptance.mbt`、`--baseline-report` CLI。

## 1. TP/FP/FN 口径

**规则**："0 FP" 不可单独验收。每次回归必须固定语料版本（commit pin），并以
"修复前/修复后"样例对分别记录：

| 分类 | 定义 | 采集方式 |
|---|---|---|
| TP | finding 对应真实可利用/需修复的模式 | 人工确认或已合并修复 PR 的前置形态 |
| FP | finding 对应安全模式（消毒/白名单/常量） | 人工确认 → 计入规则精度债 |
| FN | 已知漏洞模式未报 | 反例集（extended_test.mbt / cases 目录） |
| 未知调用 | 调用点无法绑定目标（call-graph unresolved） | `call-graph` 子命令输出计数 |
| 未分析范围 | 被排除的目录（FFI/examples）与解析失败文件 | scan errors + exclude 清单，**必须随报告输出** |

**TP/FP/FN 之外的强制披露**：任何回归报告必须包含 unresolved edges 数与
files_scanned/errors，缺失即报告不完整。

### 基线对比（已实现：`--baseline-report`）

```bash
moon-audit --format json -o prev.json <target>          # 第 N 次扫描
# ...代码变更...
moon-audit --baseline-report prev.json <target>          # 第 N+1 次扫描
```

按 **fingerprint**（rule_id + 代码片段 FNV，行号无关）分类：
- `new`（新增，TP 候选）／`resolved`（消失）／`unchanged`（存量）
- text 模式打印汇总；json 模式输出 `comparison` 节（含 resolved 明细）

口径说明：`new` 是 **TP 候选**而非 TP——确认需 LLM 研判或人工，
研判结果单独报告，不并入静态数字（评审要求）。

## 2. 缓存失效设计

**规则**：源文件 hash 单独不构成分析缓存 key。已实现组合函数
`analysis_cache_key(source, symbols_fingerprint)`（src/acceptance.mbt）：

```
key = FNV1a( source                      // 函数体源码
           ∥ symbols_fingerprint          // 依赖符号表指纹（见下）
           ∥ "moonbitlang/parser@0.3.18" ) // 前端版本常量
symbols_fingerprint = FNV1a( sort( fn_ret/impl_methods/struct_fields/
                                   constr_params/trait_params/
                                   fn_param_arrows/alias_arrows/
                                   fn_exists 的 key 集合 ) )
```

符号指纹覆盖 `.mbti` 摄取与依赖源码摄取的全部输入——**任何接口变更
（依赖升级、mbti 再生成）都使缓存失效**。排序保证插入序无关。

### 接入点清单（当前无缓存点；显式 IR 落地时按此接入）

| 接入点 | 位置（未来） | 缓存内容 | 失效额外因子 |
|---|---|---|---|
| 函数 IR | tyrecon 显式 FuncIr 构建处 | FuncIr/CFG | 本表 symbols_fingerprint |
| 污点摘要 | collect_func_summaries_flow 出口 | FuncTaintSummary | 被调函数摘要版本（调用图边集 hash） |
| 全项目调用图 | run_call_graph 出口 | CallGraph | 同上 + root 符号指纹 |

**注意**：跨函数摘要的 key 还必须包含其 callee 摘要的 key（摘要传递闭包），
否则"被调函数行为变化"不会失效调用方缓存——这是 Phase-3 SCC 摘要落地时
的实现约束。

## 3. 动态调用边真值（coverage ≠ 调用图）

官方 `moonbitlang/coverage` 测的是**分支覆盖**（bisect 兼容），不记录
调用点→实际 callee，因此**不能直接**作为调用图真值。需要插桩层：

### 设计（记录于案，实现排 Phase-4 验收）

1. **静态插桩**：在 `call-graph` 已识别的调用点（有 loc）注入记录调用：
   MoonBit 侧 `extern "C"` 计数器，或编译期生成 wrapper 包裹间接调用；
   直接调用可复用 coverage 的行/分支命中近似（保守下界）。
2. **记录内容**：(call-site id, callee id, 次数)——callee id 来自静态
   候选集，运行时只做选择确认，不做动态发现。
3. **指标**：
   - recall = 已观测动态边 ∩ 静态边 / 已观测动态边（静态图覆盖了多少真实执行）
   - **未被执行的静态边不算 FP**（评审明确要求）——precision 需要另设
     抽样/渗透用例，不得用未覆盖边充当误报证据。
4. **口径**：动态真值仅对"已执行配置"成立；不同 entrypoint 需分别跑
   并合并观测集。

## 4. 性能口径

"秒级"必须区分三档（未来 CI 报告按此分列）：

| 档 | 定义 | 当前状态 |
|---|---|---|
| 冷启动 | 无缓存全量（符号摄取+扫描） | 实测：mocket ~秒级（ir-stats 口径） |
| 增量 | 仅变更文件（--changed-files） | 已实现（文本级） |
| 深度 | 跨过程摘要 + 调用图 + 指针分析 | Phase-4；预算控制（节点上限/超时降级）在案 |

---

## 实现状态（2026-09-04）

- [x] `--baseline-report`：fingerprint 级 new/resolved/unchanged（text+json）
- [x] `analysis_cache_key` + `symbols_fingerprint`（单测锁定组合与序稳定性）
- [x] 本文档（口径 + 缓存接入点清单 + 动态真值插桩设计 + 性能分档）
- [ ] 动态调用边插桩实现（Phase-4 验收项）
- [ ] 摘要传递闭包失效（Phase-3 SCC 摘要落地时）
- [ ] 语料版本 pin 的自动 TP/FP 报告生成（scripts/regression.sh 扩展）

## T8.4 精度账本口径（--ledger，配合 --baseline-report）

四态语义（`build_ledger`，与测试 `t8_4_ledger_aggregation_correct` 锁定）：

| 状态 | 定义 | 计入来源 |
|---|---|---|
| tp_candidates | 新发现且未分诊 | new_findings（无 triage 记录） |
| confirmed | 已确认为真阳 | new/unchanged 且 triage[fingerprint]="confirmed" |
| fp_suspects | FP 嫌疑 | triage[fingerprint]="fp" **或** resolved（消失：上游已修或本就 FP） |
| untriaged | 存量未分诊 | unchanged（无 triage 记录） |

- 输出：按规则聚合表 + `corpus:` 汇总行（四态总数）
- **薄切边界**：CLI `--ledger` 目前传空 triage 表（new 全部计 tp_candidates、unchanged 全部
  untriaged、resolved 全部 fp_suspects）；triage 文件输入（人工/LLM 分诊结果回填）是
  T8.4 剩余项，接入后 confirmed 状态才有非零来源
- LLM 分诊结果与静态账本分开报告（评审要求）

## T8.3 属性测试口径

- 依赖：moonbitlang/quickcheck@0.14.0（`import ... for "test"`，官方 core 同款模式）
- 生成器只经 join 折叠构造事实（表示与生产同源 canonical：src 有序去重）
- 100 随机例 × 4 性质：join 幂等/交换/结合 + leq 与 join 相容（上界）
