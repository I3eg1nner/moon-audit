# CONTEXT — 会话日志与决策记录

## 格式
每条：日期 / 阶段 / 事实或决策 / 证据。数字类结论必须可复现（命令+目标）。

---

## 2026-09-03 · Phase R 调研完成 → 进入 M1

**事实**
- 编译器开源：moonbitlang/moonbit-compiler（OCaml）。MCore IR 定义于 src/core.ml（4,854 行）。
- .core = "MCORE240123" + OCaml Marshal（core_format.ml::export）→ 跨语言消费判死刑。
- sexp 转换器 dump_serialized_from_t 存在但无 CLI 暴露 → 上游 PR 机会。
- moonbit-docs/RFCs 无 IR 文档；mooncakes 无同类工具；starlint 为质量向 lint（无 IR）。
- MCore 指令集提炼（见 RESEARCH.md）：Cexpr_as（trait 对象）、Cexpr_apply（调用带解析目标）、
  Cexpr_function（闭包）、Cexpr_loop/break/continue、Cexpr_handle_error —— 自建 HIR 的规范参照。

**决策**
- 主路线：AST→HIR 自建（部署哲学不变：纯 MoonBit、独立二进制）。
- 次路线（机会主义）：上游 --dump-core-sexp PR，合入后未来做可选高保真后端。
- 配置型规则（CWE-614/942/770）永不迁移 IR。
- HIR 指令集设计以 core.ml 为蓝本，不 parse Marshal。

## 2026-09-03 · M1 spike 执行与验证（单会话完成）

**产出**
- src/ir_types.mbt：参数化 IRType（IRConcrete 带 Array[IRType] 泛型参数，保留元素类型）
- src/tyrecon.mbt（~1,300 行）：两遍式引擎
  - Pass A 模块级符号表：fn_ret / impl_methods("SelfTy::method") / constructors /
    struct_fields / constr_params(构造器 payload) / trait_params / fn_param_arrows / alias_arrows
  - Pass B 局部类型传播：参数标注→let 链→字面量/构造器/Record/元组索引/字段访问/
    builtin 方法返回表/regex 绑定→String/构造器模式参数类型/**调用点闭包参数回填**
      （别名→箭头类型→闭包形参，含 DotApply receiver 槽位 off-by-one 修正）
- `ir-stats` CLI 子命令 + tyrecon_test.mbt 14 个单测
- moon.mod 0.3.0 → 0.3.1

**迭代记录（反馈闭环实例）**
| 轮 | 改进 | mocket 合并解析率 |
|---|---|---|
| 0 | 初版（每包独立符号表） | 40% |
| 1 | 模块级符号表 + 限定名静态解析 + 构造器模式类型 | 54% |
| 2 | trait 方法参数回填 + builtin 方法返回表 + regex 绑定 | 57-59% |
| 3 | 参数化 IRType（元素类型）+ Map 构造器 | 59% |
| 4 | 闭包参数回填（别名→箭头→形参）+ off-by-one 修复 | 61% |
| 5 | Constr 应用分支（`Map([])` 被解析为构造器调用） | **65%** |

**基线数字（命令：`moon-audit ir-stats <target>`，含 --details 复核）**

| 目标 | 文件 | 函数 | 调用点 | 静态解析 | 接收者具体 | 高阶 | 合并 |
|---|---|---|---|---|---|---|---|
| /data/my/mocket | 51 | 401 | 2,079 | 811/1,087 (74%) | 549/949 (57%) | 43 | **65%** |
| moon-audit 自身 | 33 | 337 | 3,169 | 1,039/1,274 (81%) | 1,531/1,893 (80%) | 2 | **81%** |

未解析残余（mocket，排除 examples/benchmarks/FFI 后 222 个接收者 + 43 高阶）根因归类：
1. 闭包参数捕获的二级传播（回调内再回调）— M2 闭包提升
2. trait 对象/泛型参数接收者 — M4 去虚化
3. 跨包类型（.mooncakes 依赖的 struct_fields 不可见）— M2 依赖类型表
4. 多段限定名（a::b::c）静态目标 — M2 修正 LongIdent 扁平化

**spike 结论**：门槛 ≥60% 达成（65%/81%），主路线可行性确认，绿灯进入 M2。
注：M1 完成线（接收者 ≥90%）需 M2 的闭包提升与依赖类型表，已在 TODO 中排期。

**验证**
- moon check：0 error（8 个既有风格警告）
- moon test --target all：114/114 × 4 targets（含新增 14 个 IR 单测）
- moon fmt：无 diff

**教训（供后续会话）**
- 批量 python replace 会静默失败——结构性修改必须用 edit 工具或带 assert
- MoonBit 语法细节：部分绑定必须 `..`；单字段位置构造器 `..` 无效需 `_`；
  多行字符串字面量不支持（测试片段须单行）；`typealias` 在 parser 0.3.18 不可解析（用 `type X = ...`）

---

## 2026-09-03 · M2 + M3 切片（同一会话续）

**M2 产出与验收**
- src/taint_flow.mbt（~950 行）：流敏感污点引擎。结构化 CFG 遍历（If/Match/Try
  fork+join 合并、Guard/While/ForEach），Taint = Clean | Tainted | TaintedParam(param)
  （参数溯源，供 M3 摘要），guard/校验精化（validated_var → then 分支 Clean），
  消毒器 + replace_all CRLF 剥离识别，插值 Source 孔（词法级标识符）动态判定
- cwe113.mbt 迁移至流引擎；旧 IterVisitor visitor 删除
- 语义对齐中发现的 MoonBit AST 事实：`fn foo` 的 body 在 DeclBody 中是裸表达式
  （非 Function 包裹），签名参数在 fun_decl.decl_params —— tyrecon 与 cwe113 均按此修正
- 验收：mocket（已修复克隆）0 FP 持平旧规则；ft1（config 字段）0 FP；
  ft2（插值污点）1 TP；115/115 × 4 targets
- ir-stats 解析率：65% → 69%（mocket）/ 84%（自举），增量来自依赖类型表 +
  Show::output 预置 + Option/Result 模式 payload + Map/Array 恒等方法表

**M3 切片产出与验收**
- collect_func_summaries_flow：流引擎结构化摘要（param → HeaderValue sink），
  替换 taint_interprocedural.mbt 的文本扫描 Phase 1；scanner 调用点一行切换
- 端到端测试：handler 污点参数 → set_custom 摘要命中 → finding ✓

**M4 状态：未启动编码**（本会话预算耗尽）。设计已定稿于 PLAN.md/TODO.md：
impl 枚举去虚化 + 闭包分配点建模 + call graph + （若可行）Andersen 约束图；
动态真值验收（moonbitlang/coverage）标准已写入 TODO。
剩余 M2/M3 尾项（接收者 ≥90%、return/field 摘要）依赖 M4 的闭包与去虚化，合并验收。

**教训**
- 语义迁移必须先写对齐测试（旧规则的 6 个 CWE-113 用例全部保留为回归）
- AST 细节靠 dbg 打印实证，不靠猜：Source 插值孔、decl_params vs Function body

## 2026-09-04 · M2.5 稳定化（外部评审驱动，全部整改）

评审指出的 6 类问题全部处理：
1. deny-warn：0 警告（修复 2 处不可达分支——String.view 误归类 Int 影响指标、
   Map/方法表重复组）；moon check/test --deny-warn 全绿
2. sanitizer 语义收紧：链式覆盖累积（\\r+\\n 双覆盖或复合序列），replace 单次不算
3. guard 极性：正向 contains(危险) 不清洁；!白名单 不清洁；== false/取反仅清洁危险缺席
4. 摘要：精确参数映射 + flow() 内统一 sink 事件（嵌套覆盖）+ 混合溯源保守降级
5. If/Match 表达式污点 join
6. 关键 AST 事实：parser Constant String = 原始转义文本（len("\r\n")==4），
   所有字面量匹配需双形式（转义串 + 控制字节）

验收：新增 7 个对抗测试；122/122 × 4 targets；deny-warn 全绿；
mocket/petgraph/自举 0 FP；解析率 69%/86%/67%（指标 bug 修复后自举 +2%）
未竟（记录于 TODO）：pipeline 双引擎统一、循环不动点、21 项目全量回归

## 2026-09-04 · M4 首切片 + 文档同步
- call-graph 子命令落地：run_call_graph（闭世界符号 + method→impl 索引 + caller 追踪）
- mocket：1,454 direct edges，69% edge coverage（与 ir-stats 合并解析率一致，交叉验证）
- 文档失真修复：README 122 测试/版本 0.3.2/pipeline+call-graph 说明；开发报告同步
- pipeline 双引擎核查结论：安全 findings 一致（均出流引擎）；旧 TaintVisitor 仅存于
  taint-analysis.txt 辅助 trace，标注遗留
- 状态修正（对齐外部评审口径）：M1 ~70%、M2 ~70%（M2.5 后）、M3 ~30%、M4 切片

## 2026-09-04 · 终局冲刺：测量口径 + using + dispatch
- 根因（重要教训）：测量子命令继承了工具仓库自身 .moon-audit.json 的 exclude
  （['_build','.mooncakes','*_test.mbt']），examples/benchmarks 混入分母 14%
- 修正后诚实基线：mocket 72%（1906 调用点）/ 自举 86% / petgraph 67%
- using 导入摄取 + dispatch 边路径（dyn → impl 枚举）落地；deny-warn + 122/122 保持


## 2026-09-05 · Phase-3sem：语义修复三连（评审漏报反例全部闭环）

**变更**（src/taint_flow.mbt）
1. 字段传播溯源化：run_flow_taint_func 参数绑定 Tainted→TaintedParam(name)；
   Field(record) 按接收者溯源分派——TaintedParam（config 直传）→ Clean，
   Tainted（source 派生）→ Tainted。旧行为（字段一律 Clean）保留配置访问静默，
   新行为让"输入→struct 字段→sink"路径可检出
2. 循环不动点：env_fingerprint（排序序列化）+ flow_to_fixpoint（≤3 遍或稳定），
   应用于 While/For/ForEach 体；Taint 格点有限，实测 2 遍内收敛
3. defer 顺序：body 先、defer 表达式后（退出路径语义）

**验收**
- 新增 4 反例单测：source 构造字段必报 / config 参数字段静默 /
  两轮循环传播必报 / defer 观察 body 写入必报 —— 全绿
- 136/136 × 4 targets（wasm/wasm-gc/js/native）；moon check --target all --deny-warn 绿
- FP 回归（git stash 前后对照，同二进制路径）：luna 全仓 crlf 6→6、
  crescent 0→0、mocket 0→0、自举 0→0 —— 零回归
- 发现：回归基线 luna=0 只扫了 workspace 成员 luna/，6 条既有检出在 sol/ 成员
  （含 via parameter 直传与方法链）——基线口径待集成阶段修订为全仓扫描

## 待续（M4 完整验收：闭包分配点建模、Andersen 或轻量替代、coverage 动态真值、FFI stub 摄取）

## 2026-09-04 · [lane: upstream] 上游 PR 工件就绪
- /tmp/mbc-pr 克隆实测：driver_config.ml Buildpkg_Opt + moon0_main.ml Core_End 双点补丁
- 复用链：Core_format.import → dump_serialized_from_t → S.print / Io.write_s（全部现成）
- 设计决策：OCaml Arg 不支持可选值 → 显式 FILE 参数 + '-'=stdout（README 记录理由）
- 局限：本环境无 opam/dune/ocaml，未编译验证；静态核对签名表见 upstream/README.md

## 2026-09-05 · Phase-2a：.mbti 完整摄取（subagent lane 执行）

**产出**（src/tyrecon.mbt + 3 个新单测）
- collect_mbti_file 完整化：Type(TypeSig→struct_fields 双 key/constructors/constr_params)、
  Trait(TraitSig→trait_params "Trait::method")、Impl(ImplSig 与方法 FuncSig 联合 join →
  impl_methods 的 trait 身份，判定条件=本地 trait 方法集 ∪ 源码 trait_params)、
  Const/Value(→新表 value_types，lookup_ident 消费)
- 源码优先规则：mbti 仅补充缺失符号（fn_exists/trait_params/struct_fields/
  value_types 全部带 !contains guard），phase2a_mbti_source_wins 测试锁定
- builtin_method_ret 降级为最后回退：接收者方法返回类型先查 get_fn_ret
  （源码+.mbti+依赖，short_key 回退），未命中才走 builtin 表
- FuncSig/TraitSig 泛型参数注册进 type_params（签名类型可映射 IRTypeParam）

**关键 mbti 事实（新教训）**
- mbti 的参数渲染为**纯类型**（`fn output(Self, String)`），命名参数（`s : String`）
  是解析错误 → 整文件被保守跳过
- 匿名参数解析为 **DiscardPositional(ty=Some(..))**——trait_params/fn_param_arrows
  的收集必须覆盖该形态，否则 mbti trait 参数回填静默失效（本任务实测踩中）

**验收数字**（ir-stats 合并解析率，二进制重建后）
| 目标 | 前 | 后 |
|---|---|---|
| /data/my/mocket | 72% (1389/1906) | **74% (1412/1906)** |
| moon-audit 自举 | 86% (3067/3560) | **86% (3102/3596)** |
- FP 持平：mocket/自举/petgraph 扫描均 No issues
- moon test --target all --deny-warn：129/129 × 4 targets

**遗留**：.mbti 版本/目标后端匹配检查、.mooncakes 内 .mbti 摄取（当前依赖走源码表）、
hardcode 表进一步瘦身（留待符号身份阶段）

## 2026-09-05 · phase-2b 符号身份 + &Trait 分派

**探明的 AST 事实**：`&Alpha` 解析为 `Type::Object(ConstrId(Ident("Alpha")))`（非 Name），
此前 type_to_ir 对 Object 一律 IRUnresolved——评审反例的根因。

**产出**
- PkgSymbols.trait_names（本地 TopTrait + mbti TraitSig 双源注册）
- type_to_ir：Object → trait_names 命中 → IRTraitObj
- mbti 摄取：qualified key（"pkg::key"）与短 key 并行注册；get_impl_method/
  get_fn_ret/get_struct_fields 注释标明 exact 优先、short_key 仅最后回退
- run_call_graph：trait_method_index（"trait::method"→[SelfTy]），dyn 位点按
  (trait, method) 身份解析，method-only 索引降为回退
- 3 个新测试：&Trait 接收者分类、端到端 dispatch 边、跨包同名不覆盖

**数字（三目标，ir-stats | call-graph）**
| 目标 | 合并解析率 | dispatch 位点 | dispatch 边 | coverage |
|---|---|---|---|---|
| mocket | 74%（持平 p2a） | 2→13 | 0→39 | 74%→75% |
| 自举 | 86% | 0 | 0 | 86% |
| petgraph | 67%→69% | 28→30 | 0（回退路径） | 67%→69% |
（petgraph 接收者具体 76%→79%、unknown 193→164：&Trait 参数从 unknown 转入 dispatch）
FP 回归：三目标 No issues 持平。132/132 × 4 targets deny-warn 绿。

**残留风险**：trait 声明晚于使用点的源文件，首次收集时 &Trait 字段类型可能已存为
IRUnresolved（第二遍扫描的参数路径已覆盖，字段表路径未完全覆盖）；
qualified key 目前仅 mbti 来源（源码收集的包身份需 moon.pkg 信息，留待后续）。

## 2026-09-05 · Phase-2+3 集成完成（integrate lane 收口）

**验证矩阵**：moon fmt 无 diff；moon check --target all --deny-warn 绿；
moon test --target all --deny-warn **136/136 × 4 targets**；工作区 clean 提交。

**三目标最终数字**（scan / ir-stats / call-graph）

| 目标 | findings | 合并解析率 | 静态(解析/总数) | 接收者具体/dispatch/unknown | 直接边 | dispatch 边 | coverage |
|---|---|---|---|---|---|---|---|
| mocket | 0 | 74% (1412/1906) | 792/1031 (76%) | 620/13/204 | 1,412 | 39 | 75% |
| 自举 | 0 | 86% (3125/3629) | 1374/1602 (85%) | 1751/0/268 | 3,125 | 0 | 86% |
| petgraph | 0 | 69% (1003/1449) | 258/472 (54%) | 745/30/164 | 1,003 | 0（回退路径） | 69% |

对比集成前：mocket 72%→74%（.mbti 摄取 +2）、dispatch 位点 2→13 且产出 39 条
去虚化边（&Trait 身份分派）；petgraph 67%→69%、unknown 193→164（&Trait 转 dispatch）。
FP 三目标持平全零。

**评审门 P2 修复**：README 测试数 122→136；TODO 重复的 M3 空段清除。
评审门结论：静态 PASS（136 测试已锁定全部反例等价形态）；本条目即其 runbook
的运行时执行记录（三命令全绿 + 三目标指标复测）。

**Phase-2+3 达成判定**：
- 五步路线第 1 步（语义与指标修正）：完成——评审反例 5/5 修复且有单测锁定
- 第 2 步（统一程序模型）：核心完成——.mbti 官方摄取（Func/Type/Trait/Impl/Const）、
  qualified+短 key 双注册、&Trait 类型化分派；残留：源码侧包身份（需 moon.pkg）、
  版本/后端匹配检查、硬编码表进一步瘦身
- 第 3 步（显式 HIR/CFG+摘要）：语义修复完成（字段溯源/循环不动点/defer 顺序），
  显式 BlockIr/工作队列未做——结构化遍历+受限不动点已达当前验收，
  SCC 递归摘要与 return/field 摘要归入下一里程碑

**下一里程碑清单（按序）**
1. 显式 HIR/CFG（BlockIr + worklist 不动点 + SCC 递归摘要 + return/field 摘要）
2. 源码侧包身份（moon.pkg 解析 → qualified key 全覆盖）+ .mbti 版本/后端 guard
3. source/sink/transfer/sanitizer 配置化（JSON，评审建议提前）
4. 指针分析协同（分配点堆抽象；先比较调用点敏感 vs 上下文无关，不预设 2-obj）
5. 验收体系：TP/FP/FN 分记 harness（scripts/regression.sh 已备）、动态调用边插桩、
   缓存失效 key 扩展（接口/后端/解析器版本/库模型/被调摘要）
6. 21 项目语料全量回归 + 推送远端 CI + mooncakes 发布 v0.3.x
7. 上游 PR：docs/ir/upstream/dump-core-sexp.patch（已起草，待 OCaml 环境编译验证）
