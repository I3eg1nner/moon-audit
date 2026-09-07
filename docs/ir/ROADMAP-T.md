# ROADMAP-T — 共享语义内核路线（第四轮评审定调，2026-09-05 落档）

> 权威结论：当前是"局部类型重建 + 数据流能力的安全扫描器"，**不是** Tai-e 式分析框架。
> 下一阶段必须建设共享语义内核；不能继续用局部 AST 特判替代完整能力。
> 本文件取代 TODO.md 中已完成的里程碑叙事，作为 T0-T8 的 live checklist。
> 依赖顺序：**T0 → T1 → T2 → T3 → T4 → T6 → T7 → T8**；T5 贯穿 T1~T4；测试建设从 T0 持续。

## 评审定义的目标（"达到 Tai-e 水平"）

在明确支持的 MoonBit 版本、后端和语言子集内，提供：统一程序模型、可复用数据流求解器、
指针分析与调用图协同、可组合库模型、多分析扩展机制、可信的精度与性能评测。
对齐的是这些**基础设施**（Tai-e 的分析管理 + 指针分析插件机制），而非单独拥有 Andersen/2-obj。
不承诺：所有语言特性/所有项目/绝对无漏报/始终秒级。不复制 JVM 特有能力（反射/Spring）；
MoonBit 的闭包、trait、错误效应、异步、FFI 必须有自己的模型。

## 零、结构性代码缺口（8 项，逐条实证）

| # | 缺口 | 现状证据（file:line，2026-09-05 @ 946a1ad） | 后果 |
|---|---|---|---|
| G1 | 抽象域合并不满足结合律（T3.1 已根除：SecurityFact join by construction 幂等/交换/结合） | `taint_or`（src/taint_flow.mbt:21）：`(Param(p), FieldRef)` 分支顺序决定结果——同参异构合并先到者胜 | 合并顺序影响溯源；不能作为可靠不动点求解基础 |
| G2 | 求值与变量绑定混在一起 | ✅ 已修复（第五轮 R3-R5）：声明级 ID + 先求值后绑定 + 分支/块作用域 + 值身份统一；c9/c10/c11/c12 全 PASS（tests/cases 逐例隔离门禁 + r3r4_*/r4_*/r5_* 单测）；同片段去重行号化修复 | 见上 |
| G3 | 错误载荷没有直接传递 | ⚠️ 部分（第五轮 R6 后）：直接载荷样例（C3）与嵌套 try 外层错误存活（c13）均已修；错误出口隔离按词法嵌套归属（不可反驳 catch 消费自己的 raise，构造器-only catch 保守传播）；**完整错误传播语义（类型精确匹配/堆副作用分出口）见 T2/T3 验收** | c13 PASS + r6_nested_try_error_exit_isolation / r6_inner_constr_only_catch_propagates_unmatched |
| G4 | 分支堆状态不隔离 | `FlowCtx::copy`（src/taint_flow.mbt:125）env/sites 拷贝但 heap **共享**；`heap_write`（:281）直接覆盖字段 |一个分支的 heap_write 可抹掉另一分支已记录污点 **G4 已根除（T2/T3 批次）：heap fork/join 弱合并 + 虚拟位点（c5 唯一 XFAIL 转绿，run.sh 0 tracked misses）**|
| G5 | 循环不是完整不动点 | `flow_to_fixpoint`（src/taint_flow.mbt:83）最多 3 遍，只比较变量环境 fingerprint（env_fingerprint 不含 heap/sites） | 较长传播链、零次循环体、堆变化不可靠 |
| G6 | 摘要不可组合 | 收集时 `ictx: None`（src/taint_flow.mbt:214）——收集期读不到其他摘要；`ret_from`（:1718-1778）生成但调用点无消费路径 | 两遍收集≠递归求解；返回值告警可能只是实参整体传播的兜底 |
| G7 | 库模型加载路径分叉 | v2 字段（cb_timing/trait_edges）仅解析；`resolve_extends`（src/taint_rules.mbt:124）合并子模型时仅 v1 形式 | 同一模型放内联/独立/extends 位置可能产生不同结果 |
| G8 | 指标与增量语义不成立 | 部分（第五轮 R7）：空候选集不再计入覆盖（unknown/no-impls）；剩余：候选边≠已绑定语义仍在口径说明中、增量只扫变更文件（src/scanner.mbt:57，caller-invalidation=not-implemented） | 覆盖率虚高已收敛至“非空候选=已分析位点”的明示口径；漏掉受影响调用者待 T7 增量 |

评审复现的两个指标反例（已确认）：
1. 默认参数中的调用缺失（`Optional(default~)` 分支不求值默认表达式）但显示 100% coverage；
2. 两个调用点仅一个建立候选集合，却因三个候选边显示 75%。

## 状态词汇表（四级，全仓库统一，T0.3）

| 级别 | 含义 | 证据要求 |
|---|---|---|
| **已解析** | 名字→类型/符号已确定 | 类型重建成功（解析率口径） |
| **已绑定** | 调用点→具体被调函数已确定 | 符号身份绑定（调用图口径，非"类型已知"） |
| **已参与求解** | 该事实进入了工作队列并影响不动点 | 求解器依赖图可追溯 |
| **已端到端验证** | 正例+负例+组合例三件套齐备 | 测试锚点，且不是 `findings.length() > 0` 型 |

禁用：把"已解析"当作"已绑定"；把"单测通过"当作"端到端验证"；未分析 ≠ 安全。

## T0 纠正验收与完成状态 ⚠️ 部分完成（第五轮 R8 降级）

### 第五轮立即整改 R1-R8（2026-09-05）
- [x] R1 原始反例恢复：c9（评审同名解构原始形态，含对照）/c10+c11+c12（match 遮蔽、块泄漏、元组重绑定）/c13（嵌套 try 原始无参形态）/c14（空候选 trait，供 R7）；新增只补充不替换，c1..c8 保留
- [x] R2 真门禁：run.sh 逐例断言（PASS 精确计数/XFAIL 注册 gap，双向漂移均非零退出）；基础设施失败 exit 2；`ANALYZER=/bin/false` 实测非零；scope 披露 0(reserved)→unknown(not-measured)
- [x] R3 按声明建立变量 ID：name_map("s<scope>:<name>")→"d<decl-id>"（共享计数器，跨分支唯一、永不重置）；env/sites/tuple_comps 全部挂声明 id；赋值改槽位不换 id。锚点：r3_same_scope_scalar_rebind_chains
- [x] R4 绑定顺序：先收集全部 RHS 分量再绑模式（c9 原始反例修复）；Match/catch/noraise 分支作用域先于模式绑定（c10）；裸块 `{let x=..; x}` 实证为 Let 节点（无 Sequence 包裹），由 Let/LetMut/LetAnd/LetFn/Sequence 各自块作用域修复（c11）。锚点：r3r4_orig_same_name_destructure_reports / r4_match_pattern_shadow_scoped / r4_block_let_does_not_leak；tests/cases c9 2/2、c10_c12 3/3
- [x] R5 值与附加信息统一身份：重绑定=新声明 id，旧分量/位点键不可达即失效（c12）。附带产品缺陷修复：dedup_findings 键加入行号（同片段不同行=不同漏洞须分别报告；fingerprint 本体保持无行号，SARIF/baseline 身份稳定）。锚点：r5_tuple_rebind_invalidates_stale_components + r5_tuple_literal_components_still_project（负对照）
- [x] R6 错误出口隔离：Try 进入时快照外层 raise 事实、body 用独立 raise 作用域、退出时恢复外层并按 catch 可反驳性决定是否传播自己的 raise（不可反驳 binder/Any catch = 全捕获；构造器-only = 保守传播）；嵌套 try 不再清除外层事实。锚点：c13 PASS(1)（评审原始无参形态，source 修正 input()）+ r6_* 两单测；c13 案例文件原用 dirty_query()（非任何 source 规则命中）——案例本身构造缺陷已一并修正
- [x] R7 调用点分类：resolve_dispatch 先解析再分类（返回非空目标集布尔）；空集 → unknown(no-impls)，不计 candidate 不入覆盖分母；同一位点不再同时 candidate+unresolved。锚点：r7_empty_candidate_set_counts_unknown（0 边/0 candidate/1 unknown）+ run.sh C14 断言（0/1 覆盖）
- [x] R8 状态收紧（本节执行：T0 维持部分完成口径、G3 更新如上、未测量输出 unknown(not-measured) 已由 R2 落地；完成项均附正例锚点）

- [x] T0.1 反例固化（第五轮升级：R1 原始形态补充 + R2 真断言门禁）→ tests/cases/（c1..c14
      一条命令重现：
      同名解构/重复求值/错误载荷/循环/分支堆/未调用闭包/defer/默认参数，
      每文件头注明 期望/当前行为 与对应 G#；C8 的默认实参调用缺失已随 T0.2(a) 修复）
- [x] T0.2 指标修正 → ir-stats: bound/candidate/unknown 分列 + unknown 四分类计数
      （ffi/cascade/higher/unsupported，--details 逐点带 reason）；
      call-graph: site coverage 分母=调用点（候选集按位点归一，修 75% 混算）+
      默认实参表达式调用点入图（Parameter::Optional default~ 经 infer_expr）；
      单测锁定：t0_default_param_call_enters_graph / t0_site_coverage_per_site_denominator；
      call-graph: 废除 edge coverage 单一百分比，改报 candidate-set 大小分布；
      增量模式输出 caller-invalidation=not-implemented 警告（G8）
- [x] T0.3 四级状态 + 降级 → 词汇表如上；TODO/CONTRACTS 超标称项降为"部分实现"
      并注明缺口（见 ROADMAP 尾部"降级记录"）
- [x] T0.4 扫描范围披露 → scan 文本/JSON 输出 analysis-scope 节
      （analyzer+parser 版本/排除项/解析失败数已实现；未支持语义计数/超时/后端/入口策略
      字段预留，非零值时必须呈现；附"未分析≠安全"注记）
- 验收：已知失败一条命令重现（`cd tests/cases && moon check`——独立可编译反例工程，
      8 样例每条标注 G# 与期望/当前行为差）；每项能力有正/负/组合例
- 实现位置：scope 披露 src/scanner.mbt build_analysis_scope + src/output.mbt（文本/JSON）；
  指标分列 src/main/main.mbt cmd_ir_stats/cmd_call_graph；反例 tests/cases/（c1–c8 每文件一类，run.sh 一条命令重现）

## T1 统一 ProgramWorld（后续分析的共同输入）

> **T1 整体状态：完成（T1.4 .mbti 限定身份除外——明确未完成；T1.1 目标后端条件遗留）。**
> 早期 commit 信息中 "completes T1 milestone" 的整体完成表述撤回：以本节逐项勾选为准。

- [x] T1a-1（2026-09-05, b629433）ProgramWorld 数据层：单一装载入口
      load_program_world（模块包 walk → 源码符号 → .mooncakes → .mbti → 库模型 →
      moon.pkg 别名 → moon_config 官方 import/moon.work）。纯增量零接线（上轮超时
      教训：薄切数据层先行，T1a-2/3 接线）；修正 wip 依赖错误（moon_config 是独立
      模块）；4 个自包含 fixture 单测。CI 教训：world 键已规范化为正斜杠
      （Windows walk_packages 产出反斜杠路径导致查询失配）。覆盖 T1.1 装载 + T1.4 统一入口的数据层部分。
- [x] T1a-2（2026-09-05）ir-stats 接线 ProgramWorld：run_ir_stats 改为消费
      world.packages/symbols/aliases（不再自行重走/重收集，装载管线
      1→5 由 load_program_world 唯一承载）。等价验收：mocket/petgraph ±0；
      自举在冻结 dfbbadb 源码上新旧二进制数字完全一致（3966/4445 等），
      工作树自扫描的 -8 位点差 = 被扫源码自身缩短（run_ir_stats 体变小），
      非行为变化。禁止项遵守：未动 call-graph/scan。
- [x] T1a-3（2026-09-05）call-graph+scan 接线 ProgramWorld：三 CLI 共享
      load_program_world（call-graph 获得与 ir-stats 相同的符号/别名事实；
      scan 消费同一文件事实，with_symbols=false——规则摘要为流引擎驱动）。
      等价验收：mocket call-graph 1502/39/393/79% ±0、petgraph ±0；自举
      -6 位点 = 自引用目标源码缩短（本提交删了 call-graph 旧闭包装载代码）；
      ir-stats mocket/petgraph ±0。附带修复 parity 缺口：call-graph 此前未
      应用库模型（lib_fn_ret/lib_callbacks），现与 ir-stats 一致。
      门禁：run.sh GATE-OK rc=0、ANALYZER=/bin/false rc=2、三目标 FP=0、
      204/204 native。下一步：T1.2 完整身份。
- [ ] T1.1 剩余：目标后端条件进入模型。
- [ ] T1.1 项目装载：官方 moon_config 处理模块/包/工作区/导入；目标后端、
      测试代码与生产代码范围显式化
- [x] T1.2 完整身份（2026-09-05，部分范围：函数/类型/trait/字段表 + 别名降级；
      局部变量 ID 已在 R3 声明级槽位实现，调用点 ID=file:line 已有）：
      WorldIdentities 派生注册表（排序去重，声明顺序无关）；
      short_key 回退受 alias_mode 控制——CLI 默认 strict（回退不命中计
      unknown(alias)，不再静默跨包绑定），--conservative-alias 保留旧行为；
      gate8 三 P2 顺手修复（重复 has_dep/canonical 探测/死回退分支）。
      验收（单测）：(a) 两包同名 Foo::m strict 下 pkgC 查询不跨绑+计数
      (b) 别名表清空后 identity 解析不变 (c) 声明顺序打乱 identity 表相等。
      实测三目标差异表（strict 为默认；数字为 supervisor 双二进制复验值，
      conservative 已验证与基线 b1847b3 数字逐项一致）：
      | 目标 | conservative（基线±0） | strict | alias 计数 |
      |---|---|---|---|
      | mocket | 1502/1906 ✓ | 1485/1906 | 44 |
      | petgraph | 1011/1449 ✓ | 944/1449 | 227 |
      | 自举 | 3976/4462 ✓（分母与 strict 同为 4462） | 3944/4462 | 55 |
      （注：工人自报的 1489/1941、1941 分母与 3975/4461 为提交前中间态，
      已由 gate9 supervisor 运行时复验纠正；两模式分母无漂移）
      解读：strict 把以前"静默绑定（可能跨包错绑）"的位点转为诚实的
      unknown(alias)——petgraph 泛型重度受影响最大（-67），这正是
      T1.2 要消除的不确定绑定；T1.4（统一 .mbti 限定身份）将把其中
      大部分转为确定绑定。
- [x] **T1c（已完成 @8020b44；gate10 P1-2 修复后唯一事实源已达成 @本 commit）= T1.3 完整签名 + T1.5 入口策略**
      —— T1.3 补记：fn_param_arrows/trait_params 的生产写入已收敛到 FnSig 派生的
      唯一写入点（store_fn_sig / materialize_trait_from_sig；.mbti Func、.mbti
      Trait、源码 TopTrait、Show 种子四路统一），不再存在并行直写；锚点
      p1fix_mbti_func_sig_via_fnsig_sole_source / p1fix_mbti_trait_params_via_fnsig_derivation
- [x] T1.3 完整签名：FnSig/FnP 模型（src/fn_sig.mbt）——参数位置/标签/可选
      （默认表达式 has_default）/泛型约束（"T : Trait" 字符串化）/返回类型/
      错误效应（none|default|typed|noraise|maybe）/异步；IRFn(String) 携带
      sig/closure 身份（无信息 IRFn 废弃）；统一读取入口 sig_arrow_args/
      sig_trait_params 替换 tyrecon 双表直读（旧表成为派生物，T1.4 移除）；
      零漂移验证：mocket 1485/1906、petgraph 944/1449 与 T1b 基线逐项一致；
      自举 4004/4527（+62 位点全部来自新增 fn_sig.mbt 源码被扫描，T1a 同款
      自增长非行为漂移）；泛型语法实证：parser 0.3.18 为 `fn [T : S] f`（前缀
      方括号），`fn f[T]` 不解析（官方 AST 文档 ast.mbt:199）
- [ ] T1.4 统一源码与接口：.mbt/.mbti/builtin-prelude/依赖库/模型经同一入口装载，
      冲突与版本不匹配有定义的处理
- [x] T1.5 入口策略：ProgramWorld.entry_kinds（moon.pkg is-main/is-test
      官方解析）+ FnSig.entry（app-main|test|library-pub|ffi-extern|internal，
      按 vis/DeclStubs/is-main 分类）；scan analysis-scope 新增 entries 披露行
      （pkg 级恒有、符号装载时含 fn 级计数）；实测 petgraph pkgs(library=7)、
      mocket pkgs(library=8) 且 ffi-extern 计数>0；披露不改行为（外部对象不
      默认安全的原则由 flow 引擎保守性承担，框架回调参数仍 Tainted）
- 验收：跨包同名/局部遮蔽/导入别名/声明顺序不改变绑定结果；scan/ir-stats/call-graph
  使用同一程序世界

## 第六轮评审后：纵深闭环阶段（D 系列，2026-09-06 起）

> 第六轮评审裁定：广度已够，深度是瓶颈——HIR 是事件层而非执行内核。
> D 系列停止横向薄切，转入纵深闭环（T2 执行内核闭环 → T4.4 指针闭环 → 收尾清理）。

### D1a BlockIr CFG 构建器（2026-09-06 完成，纯数据层零接线）
- [x] src/block_ir.mbt: AST→基本块图直接降级（不经 trace）——Block{id,stmts,succs}
      复用共享 hir.mbt Stmt；出口固定布局 entry=0/normal=1/error=2
- [x] Stmt 扩展控制变体（RetStmt/RaiseStmt/BreakStmt/ContinueStmt/DeferReg）；
      live_vars/points_to 消费端保守处理（零约束/零 kill）
- [x] 降级覆盖: Let/LetMut/LetAnd/Assign 实参临时化（T2.1 恰一次规则）/
      If/Match 分叉汇合/Try 双边近似（body-end 同时挂错误边+正常边，D1b 精确化）/
      While/For/ForEach 回边/Return→normal/Raise→error/Break/Continue→循环头/Defer 注册
- [x] validate_cfg: 悬空后继/不可达块（exits 豁免——error_exit 在无 raise 函数中
      合法不可达）/出口无语句无后继 三类结构校验
- [x] 验收: 4 单测（直线单块/If 分叉汇合/While 回边检测/Try 三出口双边）+ 284 存量零回归 = 288/288
- [ ] D1b: CFG 成为执行内核（污点/live-vars/points_to 直接消费 BlockIr，停止重走 AST）
- [ ] D1c: dump/registry 消费同一 BlockIr（不再各自重收集）

## T2 真正的 HIR/CFG（当前最重要主线）

- [x] T2.1（薄切）求值顺序：Apply/DotApply/Let 路径降级为显式语句层（src/hir.mbt Stmt/RhsKind/ValuePos）——每实参恰一次的 LetEvalTemp 结构性保证 + CallStmt/SinkStmt 追踪（hir_trace，分支副本共享）；完整等价改写鲁棒性待 T2.2 CFG 直接执行该 IR（部分实现）；
- [x] T2.3（薄切）结构化值位置：tuple 分量 (decl, idx) 与 enum 载荷 (decl, ctor, idx) 统一位置表 struct_comps 替代字符串键 tuple_comps；Match 的 Constr 模式对 Var scrutinee 经位置精确投影（Pair("safe", q) 第一分量 Clean——整体绑定会过报）；嵌套模式仍回退整体（部分实现）；
      模式右值先求完再绑定
- [ ] T2.2 完整控制流：短路/分支/模式 guard/循环/break/continue/return/
      raise/catch/noraise/各退出路径上的 defer
  - [x] T2.2（薄切）defer 退出序列（块尾 LIFO/Return 直排/函数尾兜底未捕获
        raise——被捕获 raise 保持 defers 不排空；短路 &&/||：常量 lhs 跳过 rhs
        （其 sink 不再误报）、一般 lhs 分支副本 merge、结果 join 保守；break/
        continue 携带值入 loop_exits 汇合（parser 0.3.18 无 valued-loop 形态可
        端到端观察，实现为结构能力+break 值表达式求值单测锁定）；c5(G4 分支堆)已于 G4 批次转绿（XFAIL 表归零）
        保持 XFAIL 如实
- [ ] T2.3 结构化值：tuple/enum/Option/Result/struct 的构造与投影经赋值、别名、
      返回仍保留分量关系（修 Match scrutinee 整体绑定缺口）
- [ ] T2.4 隐式行为：默认参数/运算符与索引相关调用/插值/派生方法/迭代协议入 HIR；
      不支持 → 明确诊断（不再默认安全）
- [x] T2.5 闭包转换（薄切 2026-09-06）：let/LetFn/LetAnd 绑定的闭包注册即捕获快照
      （值拷贝 taints + struct 共享 sites），body 仅在调用点执行（create≠execute，
      未调用闭包零分析副作用，t2_5_uncalled 锁定）；调用点以实参 taint 播种参数 +
      快照重放捕获（t2_5_capture_frozen_value_copy / t2_5_shared_struct_capture
      _field_mutate_visible）；参数位闭包（框架回调）保持立即执行模型。
      符号侧：ClosureSite.captures/shared_captures/capture_tys 声明期收集，
      rescan 重播种防 R4 遮蔽丢失类型；调用边标注 (shared:N)。
      遗留：递归/自引用闭包、闭包作为返回值逃逸（T4 域）、capture 深链（o.g.h）
      （创建 ≠ 执行）
- 验收：同名解构/sink 副作用/直接错误载荷三反例修复；临时变量、一致改名等
  受限等价改写不改变关键分析事实

## T3 抽象域与通用数据流求解器

- [~] T3.1 重做抽象域（薄切 2026-09-06）：SecurityFact{reach, src:有序去重来源集, unknown}（src/abstract_domain.mbt）——join=集合并 **by construction 幂等/交换/结合**（t3a_* 属性测试：幂等/交换/结合/单位元+单调+bottom）；`taint_or` 改为格 join+视图投影，**16 对全组合差分锁定零行为变化**（t3a_differential_16_pairs_vs_legacy_table，232/232，FP 三目标 0）；G1（合并非结合）就 join 算子根除——剩余：值结构与指向集合分离表示（TaintedFieldRef 暂编码 'p.f' 入 src，T4 指针约束落地时结构化）
      安全属性不混在一个枚举（修 G1：合并需幂等+交换+结合，性质测试锁定）
- [x] T3.2 状态合并：分支状态隔离 ✓（G4：heap fork/join 弱合并，2026-09-06；别名/出口分离合并仍开放）
      仅满足唯一目标条件才允许强更新
- [~] T3.3 循环不动点（薄切 2026-09-06）：SecurityFact join 稳定性判据替换指纹比较（env 活跃槽位解析视图 + loop_exits 折叠 join + **heap 事实**全量入快照——站点键语法级稳定）；预算 = min(体语句数+2, 8)，超限计 loop-fixpoint-exhausted 进 scope 披露（实测 mocket 4 / petgraph 30 / 自举 0，为强更新震荡类的诚实不完整标记）；同位点重复告警行级去重（与外层 dedup 粒度一致）；新单测 t3b_loop_convergence_under_budget（5 层跨迭代链 6 遍收敛 < 预算 8）+ t3b_budget_exhaustion_disclosed（10 层链超限披露）；三遍魔数删除——剩余：全局 worklist（循环内单遍仍 AST 序）、widening、预算耗尽时的保守上近似替代
      有限抽象或显式 widening；预算耗尽必须标记不完整
- [x] T3.4（薄切）第二种分析：活跃变量已在共享 HIR 语句层上实现（`ir-stats --live-vars`；
      src/live_vars.mbt 仅消费 Array[Stmt]，静态契约=零 taint_flow 依赖；3 单测：顺序
      kill/use、分支并集、循环回边）。TRACE 语义边界：thin 层中 temp 是值身份、decl 是
      存储别名——decl 的直接 use 需 T2.1 后续（变量读取入 trace）才完全可见。
- [ ] T3.4（余）常量传播 + 死代码组合
      （Tai-e 死代码示例为直接参照）
- 验收：合并运算性质通过测试；循环/分支/工作队列顺序不改变不动点；
  第二种分析不重新解释 AST

## T4 过程间摘要、指针分析与调用图联动

- [~] T4.1 真正消费摘要：参数→返回值/字段/错误载荷/sink 映射；自由函数与方法调用
      均覆盖（修 G6）
      ——薄切进展（84f3d82+）：ret_from 调用点消费（Apply 自由函数 + `Type::method`
      静态方法 + DotApply 接收者→param0 三形态），参数位映射（labelled/positional/
      接收者偏移），摘要命中→join 精化替换实参并集兜底（t41 判别测试：无关参数
      不再过报）；apply_param_field_sinks / field_taint 副作用同步补 DotApply 形态。
      未竟：错误载荷摘要通道、ret_from 依赖顺序（单向收集，SCC 迭代在 T4.2），
      短名摘要键跨类型碰撞待 T1.4 限定身份
- [x] T4.2 递归求解（薄切 2026-09-06）：**摘要收集消费被调摘要**（ret_from 精化 + param_sinks 传递投影，仅收集期、扫描期不变）；Tarjan SCC 调用图（fn 短名邻接，外部边丢弃、Type::method 回退短键）自底向上发射；环 SCC 按 |SCC|+2 预算迭代至并格不动点，超限计数 `not_converged` 进 analysis-scope 披露（`summary-scc-not-converged=N(measured)`）；scanner 固定两遍（P3 预收集+扫描内重收集）废除为全局单次 SCC 求解——**修复实况**：初版 Tarjan 树边回写覆盖而非取 min，DAG 调用方 SCC 静默丢失（探针定位）；直接/相互递归的既有通过实为 args-union 兜底而非消费路径（测试仍有效，但区分已由 DAG/传递用例锁定）；验收 t42_*×5：直接递归/相互递归/DAG 顺序无关+幂等/传递 sink 收敛/外部边丢弃（251/251；三目标 FP 0；crescent 5 稳定；ir-stats/call-graph 双二进制 4/4 SAME——摘要变化不影响静态解析）
- [x] T4.3 基础指针约束（薄切完成 2026-09-06, T4c-1+T4c-2）：T4c-1 数据层
  （PTAlloc/Copy/Store/Load + Andersen worklist + 收敛预算，零接线）；
  T4c-2 分派精化最小接线——接收者 pts 类型集非空时与 impl 枚举求交
  （交集空回退全枚举，永不因 pt 产生空集）；per-fn 切片函数出口求解；
  ir-stats/call-graph 各增 pt-resolved 行；2 单测（非空→B::act 精化、空→回退）；
  三目标实测 pt-resolved=0（真实 dispatch 接收者均为参数，无本函数分配——
  机制正确、语料无触发位，T4.4 过程间传播后预期非零）
      T4c-1 细节：四约束 + worklist 求解器（dirty-node 传播、预算耗尽
      converged=false 强制披露）+ Stmt 纯生成器；pt_*×5 单测（字面量分配/
      别名链收敛/参数形态/字段读写往返/预算耗尽）。
      ——剩余（T4.4）：过程间传播、容器元素/闭包环境约束、站点节点身份
      分配点用节点身份而非文件行号；**PTStore/PTLoad 再触发缺口**（gate14 P1：
      store 未登记为 value-var 的 reader、fstore 增长不唤醒 load——单向传播；
      当前无生产者发射 Store/Load 故不触达，已在 points_to.mbt 头注释标注，
      T4.4 过程间传播的前置修复项）
      ——pt-resolved 双口径（gate14 P2）：ir-stats 的 pt_resolved_dispatch 统计
      **所有带 pts 的 receiver 位点**（含具体类型如 `Map([])` 后直接 `.set` 的
      场景）；call-graph 的 pt_resolved_sites 仅统计 **dyn 分派位点**。三目标
      实测两者均 0，无解读分歧，但跨命令对比时须按此口径分别解读
- [ ] T4.4 动态发现目标：接收者与闭包指向集产生调用边，新边产生新约束；
      trait/泛型实例/用户回调参与联动
- [~] T4.5 证据来源：数据流事实记录产生位置/调用关系/模型依据，支持跨函数诊断路径
      （薄切：dump-analyses 每节 provenance——fn @ file / file:line+rule+fingerprint /
      iterations+converged；语句级与跨函数链路 provenance 留全量，见 T6.4 薄切边界）
- 验收：跨三层调用/直接与相互递归/共享对象/返回闭包/trait 对象；
  检出不依赖"所有实参污点传给所有返回值"的兜底

## T5 可执行的官方库模型与安全规则（贯穿 T1~T4）

- [x] T5.1 统一模型解析（2026-09-06）：三入口单一 parse_ruleset_json + append_ruleset 管线；
      修 G7（extends 路径 v2 回调/trait_edges/嵌套 extends 此前被 divergent 副本丢弃——判别性测试锁定）；
      冲突语义文档化（RULES-DSL.md per-field 表）；未知字段→model-warnings 披露（analysis-scope 计数）；
      extends 环检测；嵌套模型搜索目录修复（libmodels 父目录）。5 单测 t51_*；
      T 占位符修复；未知字段与未支持语义不静默丢弃
- [ ] T5.2 优先覆盖 core：Array/Map/Ref、Option/Result、字符串与字节转换，
      再迭代器；描述真实读写/返回/捕获/trait 再入
- [x] T5.3 接通回调效应（2026-09-06 薄切）：引擎消费 cb_timing——immediate 在调用点
      执行回调体（现行行为，模型门控化）；deferred **不在**创建点执行、记录
      deferred-callback 事实（"model-key@L<line>:fn[n]"，供未来效应求解器消费，
      `run_flow_taint_func` 的 `deferred_facts?` 输出通道）。抑制范围=该调用点的实参表
      （嵌套非延迟调用自动复位再恢复）；匹配为后缀名匹配（流引擎无接收者类型，诚实边界）。
      内置 core-callbacks 模型（Array::map/filter/sort_by=immediate、Iter::map=deferred）；
      无模型=默认 immediate 行为不变（t53 三测试：immediate 执行/deferred 不执行+事实/
      无模型不变）。**未竟（登记 T5.3 剩余）**：延迟回调的"推进点"执行建模（当前记录
      事实但不执行——方向为漏报）；参数/返回值/错误效应经回调的传播；接收者类型精确匹配；
      内置模型后缀碰撞（gate15 P2）：`map` 调用按后缀匹配首个 Deferred 条目命中时 `Iter::map` 恒遮蔽 `Array::map`——修复方向=精确符号匹配或最长后缀优先（opt-in 场景方向为漏报，已文档化）
- [ ] T5.4 扩展系统与框架模型：语料实际使用的文件/网络/异步/取消/FFI；
      外部对象与回调边界明确
- [x] T5.5 规则绑定完整符号与安全上下文（部分：子串清除已完成）：sanitize/escape/encode
      子串自动清污已移除——完整符号白名单（html_escape/escape_html/url_encode/encode_uri/
      crlf_strip/sanitize_header_value，语料实证）+ DSL 精确条目（sanitizer_hit）；测试 ×3
      （t5c_substring_no_longer_matches / t5c_full_symbol_whitelist_matches /
      t5c_dsl_sanitizer_entry_matches）；三目标 FP 0/0/0 + crescent 5 逐条稳定（规则分布不变）；
      未竟：HTML/URL/header/路径安全性质分别表达（挂 T5.5 后半，待 DSL kind 语义扩展）
- [ ] T5.6 统一数据流规则入口：CWE-113/路径穿越/XSS 消费共享结果；
      通用过程间分析不依赖 Web 框架标记；配置型规则留在 AST 层
- 验收：每个库模型有"类型绑定/效应传播/调用边/正负例"四类测试；
  模型位置不影响行为；未执行回调不因被创建而触发副作用

## T6 分析框架化（从扫描器到平台）

- [x] T6.1 分析注册与依赖管理：分析 ID/配置/依赖/运行范围声明，自动调度
      （薄切：AnalysisId{TaintFlow,CallGraph,PointsTo,LiveVars} + AnalysisSpec{deps,run}
      + AnalysisRegistry.run_all —— 依赖闭包/拓扑排序/memoize；三测试锁定
      t6_registry_dependency_order / _result_sharing_runs_once / _unknown_id_errors）
- [~] T6.2 统一结果访问：程序级/函数级结果稳定接口；CLI 不各自维护事实来源
      （薄切：scan 与 call-graph CLI 已改经 registry 请求（行为零变化，双二进制
      mocket/petgraph scan+cg+ir-stats 6/6 SAME）；薄切边界——适配层复用整项目
      入口点，各适配器可能重复走 load_program_world（单事实源不变），
      ir-stats/live-vars 仍直连，深化=直接传 world 进各引擎；
      gate16 残留：dump-analyses 请求全 4 分析但仅消费 TaintFlow/CallGraph 聚合，
      PointsTo/LiveVars 结果弃用且 per-fn 段重复求解同约束——深化=registry 结果
      共享消费，单次约束求解复用）
- [ ] T6.3 插件扩展点：库模型/回调/错误/污点插件响应新调用边/新对象/新指向事实
      （对齐 Tai-e 指针分析插件机制）
- [~] T6.4 调试能力：导出 HIR/CFG/调用图/指向集/摘要/分析计划；
      诊断能解释"为什么这条边或污点存在"
      薄切（T6b）：`dump-analyses` 子命令导出六文件集（analysis-plan 依赖拓扑序 /
      hir-traces / taint-findings / call-graph / points-to / live-vars），每节携带
      provenance（fn @ file / file:line+rule+fingerprint / iterations+converged）；
      T4.5 evidence 薄切落地。边界：Stmt 无源码 span，语句级 provenance 留全量
- 验收：新增分析或库模型不改核心 AST 遍历器；≥2 个分析真正共享基础设施

## T7 上下文、增量与规模优化

- [ ] T7.1 上下文策略可插拔：先上下文不敏感基线，再比较调用点/对象/闭包环境敏感；
      不预设 2-obj
- [ ] T7.2 真实增量分析：未受影响结果保留；函数体/接口/模型/入口/调用图变化
      向依赖者传播失效（修增量语义）
- [x] T7.3 薄切（值敏感指纹）：symbols_fingerprint 从仅键名扩为键名+值哈希
      （fn_ret/impl/fields/ctor/trait/arrow/alias 全表入指纹；struct_fields 内层排序归一）；
      analyzer+parser 版本常量入键——gate15 known-gap 关闭（同名换类型必变指纹，t7 单测锁定）。
      剩余：后端/模型/选项/被调摘要依赖项接入（与 T7.2 增量一起做才有消费方）；
      循环依赖下的版本管理设计
- [x] T7.4 薄切（阶段计时）：--timing 输出 world-load/symbols/analysis/output 各阶段 ms
      （load_program_world 内部打点进全局记录 + CLI 级 time 包装；scan/ir-stats/call-graph 三命令）
      剩余：峰值内存/约束数/重复传播测量与瓶颈优化；
- [x] T7.5 薄切（quick|deep 分档）：--mode quick（默认=现行为）| deep（强制非 web 项目
      走 interproc taint + SCC 摘要——现有能力组合，非新分析）；mode 进 analysis-scope 披露；
      未知 mode 显式警告不静默降级。剩余：预算上限与超时降级披露；
- 验收：修改后增量结果 = 冷启动全量结果；性能比较固定机器/版本/语料/配置

## T8 最终对标与发布门槛（测试从 T0 持续建设）

- [ ] T8.1 固定语料：记录提交与依赖版本；官方 core/async 模式 + 真实应用/库 + 人工反例
- [ ] T8.2 独立调用图观测：动态插桩不限于静态已识别调用点；动态未观测边不算静态误报
- [x] T8.3 属性测试（薄切）：quickcheck@0.14 真依赖（`for "test"` 导入），SecurityFact join 三性质+leq 相容 100 随机例×4（abstract_domain_test.mbt t8_3_*）；等价改写属性测试留余
- [ ] T8.3 等价改写属性测试：作用域/临时变量等（薄切未竟）
      模型加载一致性；自动缩减失败样例
- [x] T8.4 精度账本（薄切）：--ledger 按规则四态聚合（tp_candidates/fp_suspects/confirmed/untriaged）+corpus 汇总；CLI 传空 triage（薄切边界），triage 文件回填留余（ACCEPTANCE.md 口径节）
      LLM 分诊与静态结果分开
- [ ] T8.5 兼容矩阵：固定稳定工具链 + 升级预警；区分 OS/分析器后端/被分析程序后端
- [ ] T8.6 对照实验：语义可比小程序对照分析事实；真实项目评估效果；
      不拿 Java/MoonBit 耗时交叉宣称
- 最终门槛：完成 T0~T3 = 可信过程内内核；T4~T6 = Tai-e 式框架主要结构；
  经 T7~T8 验证后方可声称"在声明的 MoonBit 范围内达到 Tai-e 级能力"

## 降级记录（T0.3，2026-09-05）

以下能力从"完成/已实现"降级为**部分实现**（四级状态词汇）：

| 能力 | 原表述 | 降级后状态 | 缺口 |
|---|---|---|---|
| 元组结构传播 | 已实现（Tuple 逐位绑定） | 部分实现（仅 Let/Match 右值为 Tuple 字面量时逐位） | Match scrutinee 整体绑定（过报方向）；enum 载荷位置投影缺失（T2.3） |
| 错误载荷传递 | 已实现（错误载荷模式绑定） | 已端到端验证（T2 450d00e：raise 载荷直接传递；`t2_raise_direct_payload_alerts_in_catch` + C3） | 残余：err_t 的 env 并集保守界（过报方向，HIR/CFG 消解） |
| 返回摘要 | ret_from 已生成 | 部分实现（已生成未消费） | G6：调用点无消费路径，返回值告警可能来自实参兜底 |
| 立即回调 | 库模型 v2 回调分类 | 部分实现（仅解析已分类，求解未接线） | 延迟回调（Iter::map）按即时处理；trait 再入边未入调用图 |
| 调用图 | CHA+去虚化 | 部分实现（候选边 ≠ 已绑定） | G8：候选边计入 coverage 口径虚高；短名匹配未废除 |

---

## 终局收尾（2026-09-06 integrate16）— T1-T8 状态总表

| 阶段 | 状态 | 薄切交付 | 留余（按依赖排序） |
|---|---|---|---|
| R1-R8（五轮评审反例） | ✅ 全闭环 | 12/12 反例 PASS，XFAIL=0；run.sh 真门禁（rc 0/1/2 语义） | — |
| T1 程序世界 | ✅（T1.4 除外） | ProgramWorld 单一装载；身份层+别名降级（strict 默认）；FnSig 完整签名；入口策略披露 | T1.4 .mbti 限定身份（灭 petgraph alias=227 池的钥匙） |
| T2 HIR/CFG | ✅ 薄切 | 语句层（求值恰一次+位置寻址）；defer LIFO/短路/携带值；G4 分支堆隔离 | 闭包转换完整化（LetMut 创建期执行/trace 双 CallStmt）；完整 CFG 边集 |
| T3 求解器 | ✅ 薄切 | SecurityFact 格域（join by construction，G1 根除）；单调循环不动点+预算；活跃变量（框架复用首证） | 常量传播/死代码组合；强/弱更新条件形式化 |
| T4 过程间 | ✅ 薄切 | ret_from 调用点消费；Tarjan SCC 迭代摘要；Andersen 约束层+指向驱动分派接线 | 摘要跨层消费的指针传播（T4.4 深化）；Store/Load 再触发 |
| T5 库模型 | ✅（1/3/5） | 三入口单管线（extends 分叉修复）；回调时机 immediate/deferred；子串清污删除 | core 全覆盖（T5.2）；异步/FFI 边界模型（T5.4）；内置模型后缀遮蔽 |
| T6 框架化 | ✅ 薄切 | 分析注册表（依赖拓扑调度）；统一结果访问；dump-analyses 六文件 provenance 导出 | registry 结果共享消费；插件响应新事实 |
| T7 规模优化 | ✅（3/4/5） | --timing 阶段计时；quick|deep 分档；值敏感指纹 | 上下文策略比较（T7.1）；真实增量（T7.2） |
| T8 对标评估 | ✅（3/4 薄切） | quickcheck 属性测试（100 随机例）；--ledger 精度账本四态 | 固定语料版本化（T8.1）；动态调用观测（T8.2）；兼容矩阵（T8.5）；对照实验（T8.6） |

**判定基础已备**（评审四条）：支持范围明确（analysis-scope 披露）/ 反例闭环（12/12）/ 多分析共享基础设施（HIR+格域+registry 三层）/ 指针-调用图-摘要-库模型协同薄切 / 精度与性能可复现（ledger+timing+284 测试+CI 三平台）。
**离"Tai-e 级"声明的剩余主要工作**：T4.4 深化（真实指针传播进摘要）+ T7.1/T7.2（上下文比较与增量）+ T8.2（动态真值实验）。
