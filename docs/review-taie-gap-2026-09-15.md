# moon-audit 与 Tai-e 的差距检查（2026-09-15）

## 结论

当前项目已具备 MoonBit 安全扫描器的实际能力，以及静态分析框架的多个组件：程序世界、HIR/CFG、流敏感污点、SCC 摘要、指向约束求解、调用图、规则 DSL、分析注册表和 SARIF 输出。

但这些组件尚未形成 Tai-e 式的统一分析内核。主要差距是程序身份与语义的正确性、指针/调用图/污点之间的协同，以及端到端验证。当前不能据“六阶段收口”记录认定达到 Tai-e 级能力，也不适合给出一个缺乏测量依据的整体完成百分比。

本次尤其确认：

1. **不同类型的同名方法会共用摘要，已复现漏报和误报。**
2. **CallSite(1) 尚未实际实现上下文区分，却返回 implemented=true。**
3. **CFG 尚未独立产生扫描告警；新增自计算仍依赖 AST 事实且未随块状态求值。**
4. **磁盘缓存有独立读写 API，但没有接入生产扫描。**
5. **自动动态调用采集尚未完成，探针上的 100% recall 无法支撑真实项目结论。**

## 范围与证据口径

- 项目基线：`66cab8e`，检查开始时工作区干净。
- 本地工具链：moon `0.1.20260807`，moonc `v0.10.7+bc794d341`。
- Tai-e 基线：官方稳定版 **0.5.4** 的源码；污点配置另参照官方 current 文档，页面标为 `0.5.5-SNAPSHOT`。
- 本次运行 native 单测、构建、现有反例门禁、CLI 回归、三个外部项目的 deep 扫描、两个项目的调用图，以及一个新建于临时目录的可编译反例。
- 本次没有运行 Tai-e 的 Java 基准程序，也没有重跑其他操作系统、其他后端或全部历史语料。下面的调用点覆盖率不是动态 recall，零告警不是零误报率或安全证明。
- 原始扫描结果和反例保存在 `/tmp/moon-audit-taie-review-20260915-qa78k6ss/`；下文提供反例全文，便于临时文件失效后重建。

## 一、最高优先级：摘要身份冲突会改变扫描结论

### 代码证据

- [summary_scc.mbt](../src/summary_scc.mbt)：`SummaryUnit.name` 使用短名；`extract_summary_units` 第 31、53 行丢失所属类型；`collect_one_unit` 第 381 行起找到第一个同名定义便返回。
- [taint_flow.mbt](../src/taint_flow.mbt)：`summary_lookup` 第 2998 行起把 `Type::method` 回退到 `method`，`apply_ret_from` 用这个摘要精化返回值污点。

这不只是调用图显示不精确：错误摘要可以把有污点的返回值判为干净，造成漏报。

### 可编译反例

创建空 `moon.pkg`，`moon.mod` 内容为：

```toml
name = "review/summary-collision"
version = "0.1.0"
```

`taint-rules.json`：

```json
{
  "sources": [{"method": "source", "kind": "RequestData"}],
  "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}]
}
```

`case.mbt`（以下行号对应实测）：

```moonbit
struct First {}
struct Second {}
fn First::pick(a : String, b : String) -> String { ignore(b); a }
fn Second::pick(a : String, b : String) -> String { ignore(a); b }
fn Second::pick_unique(a : String, b : String) -> String { ignore(a); b }
fn source() -> String { "tainted" }
fn sink(value : String) -> Unit { ignore(value) }
fn collision_should_alert() -> Unit {
  sink(Second::pick("safe", source()))
}
fn unique_should_alert() -> Unit {
  sink(Second::pick_unique("safe", source()))
}
fn collision_should_be_clean() -> Unit {
  sink(Second::pick(source(), "safe"))
}
```

运行 `moon check`：退出 0。随后运行：

```bash
moon-audit --format json --mode deep --context-strategy insensitive <fixture>
moon-audit --format json --mode deep --context-strategy call-site-1 <fixture>
```

| 调用位置 | 按上述 source/sink 配置应有的结果 | insensitive 实测 | call-site-1 实测 |
| --- | --- | --- | --- |
| 第 9 行，Second::pick 返回 source() | 告警 | **漏报** | **漏报** |
| 第 12 行，唯一名称的对照方法返回 source() | 告警 | 告警 | 告警 |
| 第 15 行，Second::pick 返回常量 safe | 无告警 | **误报** | **误报** |

只把未被调用的 `First::pick` 重命名为 `First::pick_first`，实测告警立即恢复为第 **9、12** 行，第 15 行消失。这确认了同名摘要冲突的因果关系。

**验收建议：**统一使用包含模块、包、所属类型/trait、定义位置的函数身份；SCC、摘要、调用图、指针节点与缓存使用同一身份。无法唯一绑定时不得用任意短名摘要清除污点。增加同名方法、跨包同名函数、文件/声明顺序变化的端到端测试。

## 二、核心能力对照

### 1. 上下文敏感：当前仍是骨架

[types.mbt](../src/types.mbt) 第 91 行将 `CallSite(1)` 标为已实现，但：

- [taint_flow.mbt](../src/taint_flow.mbt) 的 `cur_callsite` 在全部四处上下文构造中均为 `""`，没有实际调用点上下文生成路径。
- [summary_scc.mbt](../src/summary_scc.mbt) 的 `strategy` 只参与是否警告，不改变摘要创建、键或求解过程。
- [tyrecon.mbt](../src/tyrecon.mbt) 的 `pt_solve_all` 同样只用策略控制警告。
- [tyrecon_test.mbt](../src/tyrecon_test.mbt) 第 1394 行测试手工写入 `helper@caller_a:10`，调用的是测试文件内另写的 `summary_lookup_for_test`；它没有验证生产求解器生成或消费上下文，也未验证精度差异。

Tai-e 的求解器会在发现调用时选择被调方法上下文，并用携带上下文的变量、方法和对象传递实参、返回值和堆事实，见 [0.5.4 DefaultSolver](https://github.com/pascal-lab/Tai-e/blob/v0.5.4/src/main/java/pascal/taie/analysis/pta/core/solver/DefaultSolver.java)。

**差距：**需要真实的上下文节点和传播机制；不能只增加字符串查询分支或将 `is_implemented` 改为 true。

### 2. CFG：有结构和求解循环，尚非独立语义内核

[taint_flow.mbt](../src/taint_flow.mbt) 第 924 行先调用 `flow(body, ctx)` 产生候选告警和临时事实，之后才调用 CFG 分类与不可达过滤。

[block_exec.mbt](../src/block_exec.mbt) 第 355 行起的实现仍有以下限制：

- 输入包含 AST walk 产生的 `temp_facts`，第 392 行复制后再合并自计算结果。
- `param_st` 来自函数体内部分 `Let` 模式，不是函数签名中的真实形参初始化。
- 表达式事实在执行 CFG 之前统一计算；块内执行更新的 `st` 不会重新计算这些表达式。
- `LetEvalTemp` 和 `CallStmt` 不执行表达式或调用语义；复杂表达式大多直接返回 `Tainted`。
- 最终完整 Finding 仍来自 AST；CFG 的生产作用主要是结构性不可达过滤。

本次既有反例整体扫描为 `cfg-executed=22, cfg-divergent=2`，不是全函数零分歧；新摘要反例的 `--cfg-verify` 返回 2，`cfg-divergent=1`。

**差距：**将表达式、实参/返回值、堆读写、异常和清理路径降低为有明确语义的指令，在块执行时按当前输入事实计算。`ast-fallback=0` 或 CFG 可以构建，不等于语义完整或告警由 CFG 独立生成。

### 3. 指向分析与调用图：有增益，但跨过程精度及主链路整合不足

已确认存在 Andersen 风格的 Alloc/Copy/Store/Load 求解、Store/Load 再触发、跨文件批量收集与多轮反馈，不应再归类为“没有指针分析”。

但 [tyrecon.mbt](../src/tyrecon.mbt) 第 2380 行起在生成跨过程返回摘要时把分配点压成类型集合；第 2420 行之后的实参/返回值注入使用 `Type@ipc`。不同调用、不同分配点的同类型对象会合并，跨过程对象身份和字段图没有按原身份完整传递。

更关键的是，[scanner.mbt](../src/scanner.mbt) 第 4 行使用 `with_symbols=false` 装载，扫描入口明确不消费 world 的符号分析结果。污点 SCC 的边来自独立 AST callee 收集器；注册表中的 PointsTo/CallGraph 结果没有传给污点分析。当前“指针改进了调用图”不能直接等同于“污点分析获得同样的调用目标与堆精度”。

Tai-e 则在同一求解循环中处理新指向事实、字段/数组访问和新调用边，建立实参到形参及返回值边，见上述 [DefaultSolver](https://github.com/pascal-lab/Tai-e/blob/v0.5.4/src/main/java/pascal/taie/analysis/pta/core/solver/DefaultSolver.java)。

### 4. 插件系统：当前是分析调度注册表

[analysis_api.mbt](../src/analysis_api.mbt) 第 77 行的 runner 签名为 `(ProgramWorld) -> AnalysisResult`，不能通过该接口读取已调度的依赖结果；第 179 行仅传 `world`；默认五项分析的 `deps` 都为空，分析身份也使用固定枚举。

它已经实现依赖规划和一次运行内的调度，仍缺少共享事实访问以及“新指向集/新调用边/新可达方法”触发机制。Tai-e 的 [Plugin 接口](https://github.com/pascal-lab/Tai-e/blob/v0.5.4/src/main/java/pascal/taie/analysis/pta/plugin/Plugin.java) 提供这些事件，插件可以继续向求解器补充事实。

**验收建议：**新分析无需改核心枚举即可注册；依赖结果被真正复用；用一个会响应新增调用边并添加约束的小插件证明交互式求解能力。

### 5. 前端、DSL 与库模型：覆盖面和绑定精度仍有限

- 前端依赖 parser `0.3.18` 加自建类型恢复。本次 async 仍产生 39 条解析诊断并返回 2，不能将零告警解释为扫描成功。
- [taint_rules.mbt](../src/taint_rules.mbt) 的主要配置是方法名、kind 和整数 value_slot；没有通用的 from/to transfer 结构。source/sanitizer 查询主要按传入的方法名称命中。
- 延迟回调查询存在后缀匹配，源码明确说明污点引擎没有 receiver 类型，无法可靠区分 `Array::map` 与 `Iter::map` 等同名 API 的执行时机。
- async 模型以方法返回类型、source/sink 和 immediate/deferred 标签为主；这些条目不能证明任务执行、channel 消息传递、取消与异常传播已经建模完整。

Tai-e 官方污点配置支持方法/字段签名、调用源/参数源/字段源、字段及数组位置、显式传播配置和污点流图，参见 [官方污点文档（current）](https://tai-e.pascal-lab.net/docs/current/reference/en/taint-analysis.html)。

MoonBit 与 Java 的语言和生态不同，因此不把缺少 Java 反射或 Android 支持本身列为 moon-audit 的缺陷；应对齐 MoonBit 的 trait、泛型、闭包、FFI、async 与库入口语义。

## 三、项目自有完成声明需要修正

### 磁盘缓存

[incremental_cache.mbt](../src/incremental_cache.mbt) 第 280、311 行存在读写函数，但源码中除测试外无生产调用；[scanner.mbt](../src/scanner.mbt) 第 28 行仍每次 `FnCache::new()`。新反例连续两次独立扫描后没有生成 `.moon-audit-cache`。

当前磁盘格式只恢复零告警函数的空结果，不存完整告警、IR、摘要或指向集。因此“读写往返单测通过”不等于跨进程增量扫描完成。`--changed-files` 也只是限制报告文件，尚不能等同于对受影响调用者进行增量重分析。

这是相对项目 P6 计划的差距；本次并未确认 Tai-e 提供任意源码变化下的完整增量分析，不将它列为 Tai-e 独有能力。

### 动态调用评估

[instrument.mbt](../src/instrument.mbt) 开头明确说明不改写源码，输出 runtime 和函数报告供手工插桩。没有自动维护 caller/callee 栈的采集路径。

另有两个接口缺口：

- `instrument-calls` 有分发分支和实现，却没有子命令注册；本次实际调用返回 2。
- 该实现输出 `{"edge": ...}` 对象数组，而 `parse_static_edges` 只接受字符串数组，格式尚未闭合。

计划中 22 函数、37 条边的探针数字只能作为该探针的历史记录，不能代表真实程序 recall。静态边被动态观测到的比例应称“动态观测比例”，不能当作真值完备条件下的 precision；未执行边既不能直接判 FP，也不能仅凭未观测就确认其确为冷路径。

### 性能与文档

- [CONTEXT.md](ir/CONTEXT.md) 把 debug 二进制测量称为 Release 基准，同时声称工具链没有 release 选项。本次 `moon build --help` 明确列出 `--release`；应以实际 release 构建重新测量。
- [COMPARISON.md](ir/COMPARISON.md) 的“moon-audit 无 IR、文本式污点”已过时；另一方面，最新收口记录又高估上下文敏感、缓存和 CFG 独立性。
- 建议每项能力固定记录四个状态：数据结构存在、生产路径接入、端到端反例通过、真实语料验证，并链接同一版本的证据。

## 四、本次实际验证

### 测试

| 检查 | 本次结果 |
| --- | --- |
| `moon test --target native --deny-warn` | **402/402 通过** |
| `moon build --target native` | 通过 |
| `bash tests/cases/run.sh` | GATE-OK，既有断言通过；整体扫描有 2 个 CFG 分歧 |
| `python3 scripts/cli_regression_test.py` | 18 个测试方法中，1 个方法的 JSON/SARIF 两个子用例失败；退出 1 |
| 新摘要冲突反例 `moon check` | 通过 |
| 摘要反例与唯一名对照 | 确认 1 个漏报和 1 个误报；改掉无关同名方法后恢复 |

CLI 失败位置是 [cli_regression_test.py](../scripts/cli_regression_test.py) 第 71 行：测试预期 `call-site-1` 的 not implemented 提示，但当前 implemented=true 抑制了提示。单看失败可以怀疑测试过时，结合本次生产代码核验则说明实现状态声明提前了。

### 外部项目

均使用当前 native debug 二进制；扫描参数 `--format json --mode deep`，调用图使用默认 strict 模式。

| 项目 | 扫描告警 | 解析诊断 | scan 退出码 | 调用点覆盖率 | unresolved edges | 指向分析缩小分派目标的调用点 |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| mocket | 0 | 0 | 0 | 1497/1941，77% | 444 | 10 |
| crescent | 5 | 0 | 0 | 1390/2193，63% | 803 | 15 |
| async | 0 | 39 | 2 | 本次未运行 | — | — |

语料提交：

- mocket：`af354b7a031ee8e0a7e62e76875b82a0a39ac71b`
- crescent：`5836fe842809e4a1117910581bbc725e09fa9a20`
- async：`4fa32e85f2055e1b5c94c78337659d4a49e722af`

以上覆盖率沿用工具输出口径，包含有候选目标集合的调用点，不是唯一绑定率或正确性证明。crescent 的 5 条本次仅核对数量，没有重新人工分诊为 TP。

## 五、建议推进顺序与验收标准

| 顺序 | 工作 | 通过标准 |
| --- | --- | --- |
| P0 | 修正函数/方法身份与错误摘要精化 | 本报告反例、跨包同名反例通过；重命名无关符号、调整文件顺序不改变结论 |
| P0 | 修正 implemented 与完成文档，恢复 CLI 回归 | 行为、诊断和文档一致；18 项 CLI 测试通过 |
| P1 | 完成 CFG 独立语义执行及前端兼容性 | 不输入 AST 污点事实也能产生告警；分支、循环、返回、异常、defer、闭包正负例成立；async 解析与语义回归通过 |
| P1 | 统一指针、调用图与污点的身份及事实 | 跨调用保持对象分配点和字段事实；新目标触发参数/返回/堆传播，污点结果实际消费它们 |
| P1 | 实现真实 CallSite(1) | 自动生成不同上下文；两个调用点的堆/返回事实确实隔离；比较精度、事实规模和耗时 |
| P2 | 完善共享结果 API 和事件插件 | 插件无需修改求解器即可消费新事实、增加约束并继续收敛 |
| P2 | 补全模型、真实动态观测和固定语料评估 | 按完整符号身份绑定；自动采集独立于静态候选集的调用；保留漏边与未观测边清单 |
| P2 | 接入缓存并重测 release 性能 | 两次独立进程真实命中；被调函数/规则/模型/前端变化后结果等于冷启动全量；报告固定语料、多轮耗时和内存 |

最有价值的下一步是先消除会改变安全结论的身份与语义错误，然后让已有分析组件真正共享结果。更多规则、更多完成标记或更高测试总数，均不能代替这些验收。
