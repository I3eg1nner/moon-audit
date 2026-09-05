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
- [ ] M1 完成线（接收者 ≥90%）：依赖 M2 的闭包提升 + 依赖类型表（排期到 M2 一起验收）

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
- [ ] 21 项目全量语料 precision/recall 回归 → 推送前跑（本地仅 3 目标 0 FP）

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
- [ ] 摘要扩展：return/field 流（HeaderValue 之外），依赖 M4 call graph 定位 callee body

## Phase M3：bottom-up 摘要
- [ ] FuncSummary（param taint in → return/field/sink out）
- [ ] 替换 taint_interprocedural.mbt 文本摘要，API 不变
- [ ] 验收：跨 2 层调用污点路径可追踪

## Phase M4：指针分析 + call graph（含动态真值验收）
- [ ] Andersen subset constraints + worklist（若范围需裁剪，在 CONTEXT.md 记录理由）
- [ ] 闭世界去虚化（枚举模块+依赖源码全部 impl Trait for T）
- [ ] 闭包按分配点建模（closure var 调用可解析到分配点 body）
- [ ] 验收（静态）：输入→存 struct→跨 3 层调用→sink 可追踪
- [ ] 验收（动态，Tai-e 论文同款）：用 moonbitlang/coverage 插桩获取动态
      方法/调用边真值，测量 call graph 的 recall/precision，对齐 Tai-e 参考值
      （edges recall 91.3% / methods 95.9%，ISSTA'23 Table 1）

## Phase M5：上下文敏感 + 污点 DSL
- [ ] 2-obj 上下文敏感
- [ ] source/sink/transfer/sanitizer JSON 配置
- [ ] 数据流规则全部配置化

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
- [ ] 已知漏报（记录为 M3 显式 HIR 验收用例）：字段传播、两轮循环传播、&Trait 接收者
- [x] .mbti 摄取切片：mbti_parser 官方解析，FuncSig（含 SelfTy::method）注册
      fn_exists/fn_ret/fn_param_arrows；递归扫描项目 .mbti（moon info 产物）；
      单测锁定"接口签名成为可解析静态目标"；自举 3,057→3,067 边
- [ ] .mbti 完整摄取：Type/Trait/Impl/Const Sig、版本与目标后端匹配检查、
      逐步替换 builtin_method_ret/struct_fields 硬编码
- [ ] 完整符号身份（包/类型/trait 身份 ID），取消 short_key 后缀匹配作正式依据
- [ ] 指标口径分离：解析率（类型重建）vs 调用图准确率（方法绑定）

## 上游机会（随时可做，独立于主线）
- [x] 上游 PR 准备完成：dump-core-sexp.patch（2 文件 +18/-1，静态核对全部签名）+
      upstream/README.md（动机/用法/验证步骤/PR 草稿）——待有 OCaml 环境编译验证后提交 PR
