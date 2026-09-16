# moon-audit 与 Tai-e 差距复核（2026-09-16）

## 结论

检查版本为 **`5b2d867`**，相对[上次检查](review-taie-gap-2026-09-15.md)的 `66cab8e` 新增 7 个提交。

项目已有实际可用的 MoonBit 安全扫描能力，以及 HIR/CFG、摘要、指向分析、调用图和分析调度组件。这一轮确实修复了上次的特定同名方法反例，并接入了缓存和共享结果接口。

**但距离 Tai-e 式统一分析框架的主要差距仍然存在：函数身份未全局唯一，CFG 未独立承担告警语义，上下文敏感未形成独立事实，指针/调用图/污点尚未协同求解。** 新接口和完成标记仍多于生产路径上的有效能力。

本次新增确认的高优先级问题：

1. 不同包的同名函数仍共用摘要，已复现一处漏报和一处误报。
2. 新的 CallSite(1) 代码会设置调用位置，但普通调用没有生成按上下文区分的摘要，求解策略仍不随选项改变。
3. CFG 的按需求值被预计算表遮蔽，最简单的常量变量传入 sink 都会产生 AST/CFG 分歧。
4. 默认注册表丢弃了新增的事件总线；直接调用有事件，经注册表调用没有。
5. 磁盘缓存首轮可写、次轮可命中，但目录已存在时后续保存直接返回，缓存无法更新。
6. `pt-resolved` 把“指向集合非空”计作“缩小调用目标集合”，精度收益数字虚高。

本次只新增审查报告和[结构化证据](metrics/taie-review-2026-09-16.json)，没有修改生产代码。临时反例、独立 API 测试和完整日志位于 `/tmp/moon-audit-taie-review-20260916-jlywh6mu/`。

## 对照基线与范围

Tai-e 使用官方稳定版 **0.5.4**：

- [指针分析框架](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/pointer-analysis-framework.html)：上下文策略、堆抽象，以及求解器和插件之间的双向事实交互。
- [污点分析](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/taint-analysis.html)：依托指针分析的污点插件、签名和位置配置、传播规则、污点流图。

这些是架构与能力对照。本次没有运行 Tai-e 的 Java 基准，也没有跨语言比较耗时或宣称精度排名。MoonBit 应重点对齐包/trait 身份、泛型、闭包、FFI、async、错误和清理语义；缺少 Java/Android 专属特性本身不构成缺陷。

## 一、上次问题的复核状态

| 上次发现 | 本次进展 | 当前判定 |
| --- | --- | --- |
| First::pick / Second::pick 混用摘要 | 摘要增加 Type::method，旧反例告警恢复为第 9、12 行 | **该反例已修复**；包身份和 trait 身份仍不完整 |
| CallSite(1) 的调用键恒空 | Apply/DotApply 新增 file:line 键 | **部分实现**；普通调用不产生上下文摘要，没有策略化求解 |
| CFG 用函数体 Let 推导参数 | 改为从真实函数签名取参数 | **该初始化错误已修复**；独立执行仍未完成 |
| 磁盘缓存没有生产调用 | scan 中新增 load/save，跨进程可跳过已有空结果 | **已接入但有缺陷**；后续写入被已存在目录阻断 |
| runner 无法读依赖结果、分析 ID 固定 | 新增 AnalysisCtx.dep_results 和 Custom(String) | **API 已改善且探针通过**；默认分析未使用依赖结果 |
| 没有求解器事件接线 | 调用图新增局部回调参数 | **直接调用部分可用**；默认注册表没有转发，缺少完整事实反馈 |
| CLI 两个子用例失败 | 中间提交曾恢复 implemented=false，后续再次设为 true | **当前仍失败** |

## 二、P0：跨包摘要冲突仍导致漏报

### 根因

[summary_scc.mbt](../src/summary_scc.mbt) 第 32–34 行的普通函数身份仍是 `fun_decl.name.name`；方法身份为 `Type::method`，均没有包路径。第 421 行的 `collect_one_unit` 遇到第一个同名定义即返回。全项目的摘要单元被放入同一 SCC/摘要映射，因此不同包的合法同名定义仍会冲突。

### 最小反例

项目 `moon.mod`：

```toml
name = "review/cross_package"
version = "0.1.0"
```

根目录、`a/`、`b/` 分别放置空 `moon.pkg`；根目录 `taint-rules.json`：

```json
{
  "sources": [{"method": "source", "kind": "RequestData"}],
  "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}]
}
```

`a/a.mbt`：

```moonbit
pub fn pick(a : String, b : String) -> String { ignore(b); a }
```

`b/b.mbt`：

```moonbit
fn pick(a : String, b : String) -> String { ignore(a); b }
fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub fn should_alert() -> Unit {
  sink(pick("safe", source()))
}
pub fn should_be_clean() -> Unit {
  sink(pick(source(), "safe"))
}
```

`moon check` 成功。运行 `moon-audit --format json --mode deep <fixture>`：

| 位置 | 应有结果 | 当前结果 |
| --- | --- | --- |
| b/b.mbt:5 | source() 返回值进入 sink，应报告 | **漏报** |
| b/b.mbt:8 | 返回常量 safe，应无告警 | **误报** |

只将 `a/a.mbt` 中未被调用的 `pick` 改名为 `unrelated_pick`，告警立即变成正确的第 5 行。清空临时缓存后使用 `--context-strategy call-site-1`，仍错误地仅报告第 8 行。

**验收要求：**在包、类型、trait 和定义身份层面统一函数 ID；摘要、SCC、调用图、指针节点、缓存共用同一身份。加入跨包同名、同类型不同 trait 同名方法、声明/文件顺序变化以及无关符号重命名测试。

## 三、P1：上下文敏感仍未形成实际求解能力

本次不能再说“调用键始终为空”：[taint_flow.mbt](../src/taint_flow.mbt) 第 1451 行确实设置 `file:line`，第 1551 行在普通调用结束后恢复。

真正的缺口在于：

- `collect_summary_func` 为每个函数新建上下文，`cur_callsite` 初始化为 `""`（第 3815 行）；它没有从调用者传入上下文，也没有基于调用者事实重分析 callee。
- 普通调用结束恢复空上下文后，函数退出处 `if ctx.cur_callsite != ""` 的上下文摘要存储分支不会执行（第 3915 行）。
- `collect_summaries_scc` 和 `pt_solve_all` 的 `strategy` 仍只控制未实现警告，不改变求解节点、传播或堆上下文。
- `file:line` 本身还不能区分同一行上的多个调用点。

在隔离副本调用真实 `collect_summaries_scc(..., strategy=CallSite(1))`：

```moonbit
fn helper(x : String) -> String { x }
pub fn dirty(x : String) -> String { helper(x) }
pub fn clean() -> String { helper("safe") }
```

实测摘要键只有 **`dirty,helper`**，按当前声明的 `name@context` 设计计数为 **0 个上下文摘要**。

新增的 `p1_ctx_callsite1_discriminates_two_callers` 测试只断言裸 `helper` 摘要存在、`ret_from` 非空和 implemented=true；没有检查上下文键或不同上下文事实。参数到返回值的关系摘要本来就能区分实参是否有污点，不能用该事实证明上下文敏感。

**应补的验收：**同一分配点被两个调用点执行时，各自的对象/字段事实能够隔离；策略切换必须改变真实求解身份，并测量精度、事实数量和成本。

## 四、P1：CFG 的按需表达式计算在主路径中被遮蔽

[block_exec.mbt](../src/block_exec.mbt) 第 145 行的 `resolve_temp` 优先查询预计算表，只有缺失时才用当前块状态 `st` 求值。然而第 389 行已经遍历 **全部** `expr_refs`，用初始形参环境预计算并合入该表。因此在 `cfg_hybrid_classify` 的当前装配路径里，有 `expr_ref` 的 temp 都已有表项，新增按当前状态求值的分支不会生效。

此外，`BindVar` 第 160 行仍直接查表；完整告警仍由 AST `flow` 生成，CFG 主要做分类比较与结构性不可达过滤。

使用同样的 sink 配置，下列通过编译的代码在普通扫描中正确地无告警，但 `--cfg-verify` 返回 **2**，`cfg-divergent=1`：

```moonbit
fn sink(value : String) -> Unit { ignore(value) }
pub fn clean() -> Unit {
  let s = "safe"
  sink(s)
}
```

现有反例门禁的整体冷扫描也仍有 **2 个 CFG 分歧**。所以“有 CFG”“参数初始化正确”和“CFG 独立产生正确告警”需要分开验收。

## 五、P1：指针/调用图/污点的主链路仍未统一

- `scan_project()` 的库入口改为 `with_symbols=true`，但[主 CLI](../src/main/main.mbt) 第 667 行仍为 `with_symbols=false`，然后通过默认注册表进入 `scan_project_with_world`。普通扫描没有获得新增符号桥接所需的完整符号表。
- [scanner.mbt](../src/scanner.mbt) 第 47 行填充 `dispatch_hints`，当前源码没有消费这些提示的分析路径。
- 默认 TaintFlow 的依赖仍为空，也没有消费 PointsTo 或 CallGraph 结果。
- 指针返回摘要新加的分配点保留条件是 `has_prefix("alloc:")`，而现有生成器主要使用 `Type@s...`、`Type@ret:...`、`Type@ipc` 等名字；该分支没有完成统一对象身份。实参传播仍降为 `pt_site_type(site) + "@ipc"`，字段图没有按原对象身份跨过程传递。

Tai-e 的核心区别是新指向事实、调用边、参数/返回值传播和插件反馈处在可继续收敛的求解循环中，而这里仍有多条相互分离的分析路径。[官方框架说明](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/pointer-analysis-framework.html)

## 六、P1：共享结果 API 有效，默认事件接线仍缺失

本次独立验证确认：注册 `Custom("producer")` 和依赖它的 `Custom("consumer")`，consumer 可以通过 `dep_results` 读取 producer 的结果，测试通过。这部分不再归类为“只有接口无能力”。

但[analysis_api.mbt](../src/analysis_api.mbt) 第 266 行的默认 CallGraph runner 忽略 `_ctx`，调用 `run_call_graph_with_world(w)` 时没有传入事件回调。

在一个通过编译、两种类型实现同一 trait、且接收者明确为其中一种类型的探针上：

| 调用方式 | 新调用边事件数 |
| --- | ---: |
| 直接 `run_call_graph_with_world(..., event_cbs=...)` | **1** |
| `default_registry().run_all(..., events=...)` | **0** |

直接 API 的回调也仅覆盖严格缩小目标集合的分派边，尚非所有新增调用边；没有新指向集事件或供插件补充求解约束的完整通道。

仓库新增事件测试仅断言 `dispatch_edges.length() >= 0`，然后忽略 `fired`，无法检出这类断线。

## 七、P1：精度指标需要重新定义

[tyrecon.mbt](../src/tyrecon.mbt) 第 3607 行正确区分是否严格缩小目标集合，但第 3655、3672、3682 行等位置只检查 `recv_pt.length() > 0` 就增加 `pt_resolved_sites`。等集甚至空交集回退到完整 CHA 候选集时，也可能被计为“已缩小”。

本次 mocket 实测：

- CLI 报告 `pt-resolved dispatch: 10`，说明文字为“narrowed the target set”。
- 直接注册在严格缩小分支中的回调，观测到 **0 条严格缩小后生成的边**。
- 同一回调在人工分派探针上能触发 1 次，排除了回调本身不可用的解释。

因此这 10 不能解释为 10 次真实精度提升。**本条也校正上次报告沿用 CLI 说明将该数解释为缩小目标集合的口径。** 应分别输出有指向信息、严格缩小、等集、空交集回退等计数。

## 八、P2：缓存已接入，但更新和诊断不完整

[incremental_cache.mbt](../src/incremental_cache.mbt) 第 286 行创建目录，任何异常都直接返回。native 的 mkdir 在目录已存在时返回错误，因此第二次及以后的 `disk_cache_save` 不会写文件。

独立 CLI 进程实测：

1. 首次扫描创建 `.moon-audit-cache/fn-cache.txt`。
2. 第二次命中零告警缓存，单函数探针 `cfg-executed` 从 1 变成 0。
3. 新增一个函数后再次扫描，新函数被分析，但缓存文件内容完全未变。

缓存命中还会跳过执行诊断的累计。mocket 冷/热扫描 `cfg-executed` 从 **386 → 70**，crescent 从 **369 → 6**，报告没有相应的缓存跳过函数计数。简单常量 sink 探针的 CFG 分歧也可随缓存命中而消失；这不能解释为语义修复。严格 `--cfg-verify` 会绕过缓存，因此仍能检出问题。

目前只缓存零告警函数的空结果，并非完整 IR/摘要/指向事实持久化；所有摘要仍在扫描前重建。源码变更后的依赖失效、两次独立进程命中、冷/热结果及覆盖诊断一致性，都应纳入验收。

缓存是本项目自己的工程目标；本次不将任意源码变化下的完整增量分析宣称为 Tai-e 已具备的能力。

## 九、其他仍然存在的差距

- **前端与语言语义：**parser 仍为 0.3.18，async 仍有 39 条解析诊断。增加 async 模型并未消除解析及错误/清理语义问题。
- **DSL 与库模型：**仍缺少 Tai-e 式完整签名、字段/数组位置和显式 transfer 的通用表达；回调时机绑定仍存在名称后缀匹配，缺少任务执行、消息传递与取消语义的端到端验证。[Tai-e 污点配置](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/taint-analysis.html)
- **动态评估：**instrument 仍是 runtime 加函数报告，未自动改写源码；instrument-calls 注册/数据格式问题未改。探针上的历史 recall 不能代表真实程序。
- **性能证据：**最新提交标题包含 release benchmarks，但此次提交没有新增对应的可复现基准样本；现有版本化样本仍是 9 月 13 日的 debug 比较。本次没有测量 release 加速比。

## 十、本次验证汇总

工具链：moon `0.1.20260807`，moonc `0.10.7+bc794d341`，Linux native。

| 检查 | 结果 |
| --- | --- |
| 当前项目 native 单测（deny-warn） | **405/405 通过** |
| native build | 通过 |
| 既有 cases 门禁，包括新增 c15 | 通过；整体冷扫描仍有 2 个 CFG 分歧 |
| CLI 回归 | 18 个测试方法中，1 个方法的 JSON/SARIF 两个子用例失败 |
| 上次类型同名反例 | 通过，报告正确的第 9、12 行 |
| 本次跨包同名反例 | 检出漏报/误报，重命名对照恢复正常 |
| 临时副本的 4 项 API 契约探针 | 共享依赖结果通过；上下文生成、注册表事件、精度指标三项失败 |

API 探针专为验证本次发现添加在临时副本，不是仓库既有 405 项测试的一部分。测试数量增加不能替代关键契约断言：不应再使用 `length >= 0`、仅验证“不崩溃”或 implemented 标记本身证明能力完成。

### 固定语料复测

为防止新缓存机制修改外部项目，扫描使用临时副本，排除已有构建和缓存目录，依赖通过原 `.mooncakes` 只读路径访问。三个原始语料工作区均干净，提交与上次一致，详见[证据 JSON](metrics/taie-review-2026-09-16.json)。

| 项目 | 扫描文件 | 告警 | 解析诊断 | 退出码 | 调用点覆盖率 | 未解析边（CLI） |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| mocket | 42 | 0 | 0 | 0 | 1497/1941，**77%** | 444 |
| crescent | 53 | 5 | 0 | 0 | 1390/2193，**63%** | 803 |
| async | 170 | 0 | 39 | 2 | 本次未运行 | — |

mocket/crescent 冷、热扫描告警和错误一致，但覆盖与预算诊断不同。调用点覆盖率包含有候选集合的调用点，不是动态 recall 或唯一正确绑定率；本次没有将零告警判为安全，也没有重新人工分诊 crescent 的五条发现。

## 建议推进顺序

1. **P0：统一全局函数身份。**先关闭跨包/trait 同名摘要混用，避免错误精化导致漏报。
2. **P1：修正完成声明、CLI 回归和指标。**上下文生成、事件触发、真实缩小目标集合应使用有区分力的断言。
3. **P1：让 CFG 按当前状态执行真实指令。**移除遮蔽按需求值的表；参数、返回、堆、异常、defer、闭包语义分别验收。
4. **P1：打通生产路径。**CLI 装载一致；污点消费调用图和指针事实；默认注册表转发事件；插件能补充事实并驱动收敛。
5. **P1：完成真实 CallSite(1)。**上下文进入方法/变量/对象身份，以可区分的堆与调用反例证明收益。
6. **P2：修复缓存生命周期，完善前端/模型和评估。**随后再做独立动态调用观测、release 性能与多平台兼容验证。

当前最准确的定位是：**已有较完整组件集合的 MoonBit 安全扫描器，正在向统一静态分析框架演进；尚不足以认定达到 Tai-e 级能力。**
