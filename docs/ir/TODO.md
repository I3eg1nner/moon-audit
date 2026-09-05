# TODO（live checklist）— IR 演进

> 规则：完成一项勾一项并把证据（数字/commit）写到 CONTEXT.md；发现新事实先更新 RESEARCH.md 再动方案。

## Phase R：调研（2026-09-03 完成）
- [x] mooncakes 全量 registry 扫描（2,328 包）：无 IR/分析类工具
- [x] moonbitlang org 88 仓库排查：锁定 moonbit-compiler（开源，OCaml）
- [x] MCore 指令集提取（core.ml，4,854 行）
- [x] .core/.mi 序列化格式判定（OCaml Marshal → 不直接消费）
- [x] dump_serialized_from_t 发现（sexp 现成、CLI 未暴露 → 上游 PR 机会）
- [x] moonbit-docs / RFCs / agent-guide 排查：无公开 IR 文档
- [x] RESEARCH.md / COMPARISON.md / PLAN.md 落盘

## Phase M1：类型重建 spike（2026-09-03 完成）
- [x] IRType 参数化核心（IRConcrete(name, args) 保留元素类型）
- [x] 模块级符号表（fn/impl/构造器/struct_fields/trait_params/fn_param_arrows/alias_arrows）
- [x] 局部类型传播（标注参数、let 链、字面量、构造器、Record、元组索引、字段、builtin 表）
- [x] 调用点闭包参数回填（别名→箭头→形参）
- [x] `ir-stats` 子命令 + 14 单测
- [x] **验收**：mocket 65% / 自举 81%（门槛 ≥60% ✅）
- [x] moon test --target all 114/114 × 4
- [x] CONTEXT.md 真实数字落盘（含 5 轮迭代记录）
- [ ] M1 完成线（接收者 ≥90%）：p4clos 完成闭包分配点切片，但 ≥90% 未达（mocket 74%）——剩余主缺口 FFI（~41% unknown）与跨包级联，下一杠杆 extern stub 摄取

## Phase M2.5：稳定化（2026-09-04 完成，评审驱动）
- [x] moon check/test --deny-warn 全绿（0 警告；修复 String.view 不可达分支等指标 bug）
- [x] sanitizer 收紧：仅 replace_all 链且需覆盖 \\r+\\n（或复合 \\r\\n）；单次 replace 不算
- [x] guard 极性修正：仅"白名单通过/危险缺席(取反)"清洁 then 分支；
      正向 contains(危险) 不再错误清污（新增对抗测试覆盖）
- [x] AST 事实记录：parser Constant String 存原始转义文本（非控制字节），匹配需双形式
- [x] If/Match 表达式污点 join（let v = if/match ... 不再漏报）
- [x] 摘要精确参数映射（仅记录实际到达 sink 的参数）+ 嵌套 sink 统一事件（flow() 内递归记录）
- [x] taint_or 混合溯源降级为 Tainted（保守）
- [x] 验收：122/122 × 4 targets；deny-warn 全绿；mocket/petgraph/自举 0 FP 持平
- [x] pipeline 核查：安全 findings 全部来自 phase1 流引擎（一致）；
      taint-analysis.txt 为辅助 trace（旧 TaintVisitor，仅报告用），已标注
- [ ] 循环不动点（当前单遍）→ 显式 IR/CFG 时实现
- [x] 21 项目语料扩容（scout21，2026-09-05）：15 新克隆成功、4 仓无 moon.mod 排除、"mio"未定位（疑改名）→ 17 语料 + 1 本地第四次快照；护栏 6×0 四次连续、crescent 5 TP 四次一致、新 11 项目全 clean、mars.mbt 9 条新检出已分诊（5 TP 候选 / 4 FP 嫌疑，详见 regression-baseline.md 第四次快照节）

## Phase M2：流敏感污点引擎（2026-09-03 核心完成，M2.5 后视为完成 ~70%）
- [x] 依赖类型表：.mooncakes 依赖源码符号摄取（+2% 解析率）+ short_key 归一化
- [x] 流敏感污点引擎（taint_flow.mbt）：结构化 CFG 遍历、分支 fork/join 合并、
      guard/校验精化（validated var → Clean）、消毒器/CRLF 剥离、插值 Source 孔
- [x] CWE-113 迁移到流引擎（IterVisitor 旧实现删除），语义对齐旧规则
      （header 值参数位、Field 安全、常量插值）+ guard 精化超越旧规则
- [x] 验收：mocket 0 FP（与旧规则持平，不升 ✓）；正例全检出；114→115 测试全绿
- [x] 多段限定名静态目标（short_key 后缀匹配）
- [ ] 接收者解析率 ≥90%：现 62%（mocket），剩余缺口 = 闭包二级传播 + FFI 文件
      → 与 M4 闭包/去虚化合并验收（闭包提升即 call graph 的一部分）
- [ ] FuncIr/BlockIr 显式 IR + 函数级缓存（结构化遍历已达成流敏感目标，
      显式 IR 推迟到真正需要 worklist 不动点时再做——记录在 CONTEXT）

## Phase M3：bottom-up 摘要（2026-09-03 切片完成）
- [x] 结构化摘要：collect_func_summaries_flow（流引擎驱动，TaintedParam 溯源）
      替换文本扫描 Phase 1，InterProceduralContext API 不变，scanner 零改动
- [x] 验收：跨函数路径（handler→set_custom 污点参数→sink）端到端测试通过
- [x] 摘要扩展（P3sum，2026-09-04）：ret_from（参数→返回值，Return 显式 + 尾表达式）、
      field_taint（r|field|src-param 字段写近似，无别名追踪——文档注明）、
      两遍收集作 SCC 不动点保守替代（scanner 预收集 pass）；调用点消费：field_taint
      → 接收者实参污点化（run_cwe113 可选 ictx，FlowCtx 携带）；
      验收：wrap 返回值流告警 + fill 字段写跨函数告警 + 负对照（无摘要=0），
      145/145 × 4 targets，三目标 0 FP 持平

## Phase M4：指针分析 + call graph（含动态真值验收）
- [ ] Andersen subset constraints + worklist（若范围需裁剪，在 CONTEXT.md 记录理由）
- [ ] 闭世界去虚化（枚举模块+依赖源码全部 impl Trait for T）
- [ ] 闭包按分配点建模（closure var 调用可解析到分配点 body）
- [ ] 验收（静态）：输入→存 struct→跨 3 层调用→sink 可追踪
- [ ] 验收（动态，Tai-e 论文同款）：用 moonbitlang/coverage 插桩获取动态
      方法/调用边真值，测量 call graph 的 recall/precision，对齐 Tai-e 参考值
      （edges recall 91.3% / methods 95.9%，ISSTA'23 Table 1）

## Phase M5：上下文敏感 + 污点 DSL（DSL 切片 2026-09-05 完成）
- [ ] 2-obj 上下文敏感
- [ ] source/sink/transfer/sanitizer JSON 配置
- [x] 污点 DSL 切片（A1，2026-09-05）：taint-rules.json / .moon-audit.json "taint" 节，
      sources/sinks(value_slot)/sanitizers 增量叠加内置表（无配置=行为完全一致，
      156 既有测试零改动验证）；引擎接线 source_hit/header_sink_hit/sanitizer_hit/
      sink_value_slot；list-rules 显示配置来源；5 个新单测（含 value_slot 槽位语义）；
      FP 三目标 0 持平；见 docs/ir/RULES-DSL.md（transfer/其他 sink kind 的边界已记录）
- [ ] 数据流规则全部配置化（剩余：transfer 规则、其他 sink kind——依赖显式 IR）

## Phase M4 切片（2026-09-04）
- [x] call-graph 子命令：闭世界 CHA（模块+依赖符号）+ 去虚化索引
      （method → impl self types），caller 追踪入 CallSiteStat
- [x] mocket 实测：1,454 direct edges / edge coverage 69%
- [x] 测量口径修正：ir-stats/call-graph 改用标准 exclude（examples/benchmarks 出分母）
      —— mocket 69%→72% 为诚实基线；根因：工具仓库自身 .moon-audit.json 的 exclude 覆盖
- [x] using 导入摄取（TopUsing → fn_exists 非限定别名）
- [x] dispatch 边路径接入（dyn 前缀 → method_index 枚举；mocket 仅 2 个 dispatch 位点，
      method 未入 impl 表时保守计 unresolved）
- [ ] M1 完成线（接收者 ≥90%）：剩余 = 闭包二级传播 + FFI（extern stub 签名摄取可部分救回）
- [ ] Andersen 约束图 / 闭包分配点建模 / coverage 动态真值验收（M4 完整验收）

## Phase M2.6：二次评审整改（2026-09-04）
- [x] 安全缺陷修复：replace_all 的 old/new 槽位语义（new 含 CRLF = 引入危险 → 毒化链，
      永不判安全）；对抗测试锁定（引入型必报 / old 槽双覆盖链仍安全）
- [x] regex-positive 精化禁用（re"^ok-" 前缀不排除后续 CRLF，非可靠性质）
- [x] PLAN 撤回"M2 超前"表述；COMPARISON 纠正所有权假设；路线按五步重排
- [x] 已知漏报三连修复（2026-09-05，Phase-3sem）：
      ① 字段传播溯源化——fn 参数改绑 TaintedParam（直传报、字段读 Clean），
         source 派生接收者（req.query 结果构造的 struct）字段传播 Tainted；
      ② 循环不动点——While/For/ForEach 体最多 3 遍或 env 指纹稳定（序列化 "k:v;" 比对），
         第 N 轮写入的污点对第 N+1 轮 sink 可见；
      ③ defer 退出路径顺序——body 先执行、defer 表达式后评估（原顺序相反）；
      验收：4 个反例单测（字段/配置静默/两轮循环/defer）全绿，136/136 × 4 targets，
      deny-warn 绿；luna 全仓扫描前后均 6 检出（stash 对照）零 FP 回归
      （基线 0 条系仅扫 luna/ 子目录，6 条在 sol/ 成员，属既有检出）
      （&Trait 接收者已由 Phase-2b 修复，见上）
- [x] .mbti 摄取切片：mbti_parser 官方解析，FuncSig（含 SelfTy::method）注册
      fn_exists/fn_ret/fn_param_arrows；递归扫描项目 .mbti（moon info 产物）；
      单测锁定"接口签名成为可解析静态目标"；自举 3,057→3,067 边
- [x] .mbti 完整摄取（2026-09-05，Phase-2a）：Type（struct 字段/构造器，双 key 注册）、
      Trait（方法签名→trait_params）、Impl+方法 FuncSig 联合 join（impl→trait 身份）、
      Const/Value（value_types 新表，lookup_ident 消费）；
      源码优先规则（mbti 仅补充，guard + 测试锁定）；
      builtin_method_ret 降为最后回退（符号表先行）
      —— mbti 事实：参数渲染为纯类型（匿名 DiscardPositional），命名参数是解析错误；
      DiscardPositional 类型必须入 trait_params/fn_param_arrows
- [x] 依赖 .mooncakes 内 .mbti 摄取（E2 完成，walk_dep_dir 收集 74 个依赖接口；
      gate3-P2 对账勾选——见上方 [x] 条目）
- [ ] .mbti 版本与目标后端匹配检查、struct_fields/constr 硬编码表的进一步替换
- [x] 完整符号身份（2026-09-05，Phase-2b）：
      · qualified key（"pkg::key"）与短 key 并行注册（mbti 来源），
        short_key 降级为最后回退（三个 getter 注释标明解析顺序）
      · 跨包同名单测：两个 pkg::Foo::act 互不覆盖（exact 优先）
      · &Trait 探明：Type::Object(ConstrId) → trait_names 表 → IRTraitObj
      · 分派索引升级 "trait::method" → [SelfTy]，dyn 位点按 trait 身份枚举
      · 评审反例锁定：&Alpha 接收者 → dispatch(trait:Alpha) + 边 f -> B::act
      · 数字：mocket dispatch 2→13 / dispatch 边 0→39 / coverage 75%；
        petgraph 67%→69%（&Trait 参数 unknown→dispatch，接收者具体 76%→79%）
      · 残留：源码收集侧包身份（需 moon.pkg）；声明晚于使用点的字段类型首收集
- [ ] 指标口径分离：解析率（类型重建）vs 调用图准确率（方法绑定）

## Phase ACCEPT：验收体系（2026-09-04 完成，评审第 4 部分）
- [x] --baseline-report <prev.json>：fingerprint 级 new/resolved/unchanged 分类
      （text 汇总 + json comparison 节）；E2E 实测（修复→resolved / 新增→TP 候选）
- [x] analysis_cache_key(source + symbols_fingerprint + parser 版本常量) +
      symbols_fingerprint（key 集合排序，插入序无关）；单测锁定
- [x] docs/ir/ACCEPTANCE.md：TP/FP/FN 口径（未知调用/未分析范围强制披露）、
      动态调用边插桩设计（coverage≠调用图真值）、性能三档口径、缓存接入点清单
- [ ] 动态插桩实现 + 摘要传递闭包失效（Phase-3/4 落地时接入，见 ACCEPTANCE.md）

## 下一里程碑（2026-09-05 E1/E2 收口后剩余，按序）
1. 显式 HIR/CFG（BlockIr + worklist 不动点 + SCC 递归摘要）
2. ~~源码侧包身份~~ ✅ E2 完成（moon.pkg 别名 + dep .mbti + LetFn）；剩 .mbti 版本/后端 guard
3. source/sink/transfer/sanitizer JSON 配置化
4. 指针分析协同（分配点堆抽象；先比较调用点敏感 vs 上下文无关，不预设 2-obj）
5. 动态调用边插桩（ACCEPTANCE.md 设计已备）
6. extern 库模型（FFI 剩余 ~79 位点，类 Tai-e reflection 模型）+
   .core 高保真后端（依赖上游 PR 合入，补丁已就绪）
7. 21 项目语料网络全量 + 推送远端 CI + mooncakes 发布 v0.3.x
8. 上游 PR 提交（patch 已备，待 OCaml 编译验证）

## Phase E2：dep .mbti 摄取 + moon.pkg 别名身份 + LetFn 闭包位点（2026-09-05）
- [x] walk_dep_dir 摄取 .mooncakes 内 74 个 .mbti（mocket 依赖：async/x/mimetype），
      源码优先原则保持（.mbti 仅补源码未注册符号）；限定键注册复用 p2a 的 qkey 机制
- [x] moon.pkg 别名身份：pkg_alias_map 解析 import 块（显式 @alias + 默认尾段别名），
      调用点 Ident(Dot) 经 ScanCtx.pkg_alias 展开为 "pkgpath::fn" 限定键（先限定后短键回退）
- [x] 源码侧限定键：register_qualified_symbols 按路径推导包身份（.mooncakes/<owner>/<repo>/...）
- [x] LetFn 注册 closure_sites（镜像 LetAnd 延迟模式；未标注体延迟到首调用点回填）
- [x] 数值 Infix 传播（Int/Double/UInt 算术防级联）
- [x] 测试 +3：dep .mbti 签名解析+接收者链 / 别名展开限定键 / LetFn higher→static
      （$closure:helper@1 目标验证）→ 155/155
- [x] 指标：mocket 74→75%（FFI/dyn 占剩余主体）、自举 86→**88%**（达标 ≥88）、
      petgraph 69% 持平；FP 三目标 0
- [ ] mocket ≥78% 未达：剩余 unknown 185 中 FFI native/js ~79 + dyn trait 分派 ~30
      （M4 去虚化域）+ 深层级联——E2 三杠杆已尽，下一杠杆为去虚化/指针分析

## Phase E1：extern stub + FFI 文件三模式（2026-09-05）
- [x] 调研结论：extern 声明（DeclStubs）签名**本就注册**（探针证实 fn_ret=Conn ✓）；
      FFI 文件 238 个未解析的真实根因是文件内普通代码的三类模式：
      1. Tuple 解构丢类型（for-in Map + let (k,v) = pair）→ 位置化绑定修复
      2. builtin 高阶方法闭包参数无 hint（Map::each((k,v)=>...)）→
         builtin_callback_params 表（按接收者参数化类型派生，槽位=实参位置）
      3. 核心 trait 静态无返回类型（Show::to_string）→ builtin_static_ret 补充
- [x] 验收：4 个单测（extern 链/Tuple/闭包 hint/trait 静态）；152/152；
      mocket 1412→1422、petgraph 976→1007；未解析 493→483（FFI 238→228）
- [ ] 残余：FFI 文件未解析主因转为深层级联（值来自 extern 返回但经 2+ 层包装），
      与跨包级联同源——E2（.mooncakes 内部 .mbti + moon.pkg 包身份）覆盖

## 上游机会（随时可做，独立于主线）
- [x] 上游 PR 准备完成：dump-core-sexp.patch（2 文件 +18/-1，静态核对全部签名）+
      upstream/README.md（动机/用法/验证步骤/PR 草稿）——待有 OCaml 环境编译验证后提交 PR
