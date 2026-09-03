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

## Phase M2：HIR + CFG + 过程内流敏感污点（下一步）
- [ ] 依赖类型表：解析 moon.pkg imports，纳入 .mooncakes 依赖源码的 struct/impl 符号
- [ ] 多段限定名（a::b::c）静态目标修正
- [ ] 闭包捕获提升（二级传播：回调内回调）
- [ ] FuncIr/BlockIr/StmtIr 定义（指令集参照 core.ml 裁剪）
- [ ] AST→HIR lower（match 降级、闭包捕获提升、错误边）
- [ ] CFG 构建 + 函数级 IR 缓存（key=内容 hash，复用 fingerprint 基建）
- [ ] 过程内流敏感污点引擎（worklist）
- [ ] CWE-113 迁移为首个 IR 规则，mocket/async FP 对比
- [ ] 验收：接收者解析率 ≥90% + guard 过滤数据流化 + FP 不升

## Phase M3：bottom-up 摘要
- [ ] FuncSummary（param taint in → return/field/sink out）
- [ ] 替换 taint_interprocedural.mbt 文本摘要，API 不变
- [ ] 验收：跨 2 层调用污点路径可追踪

## Phase M4：指针分析 + call graph
- [ ] Andersen subset constraints + worklist
- [ ] 闭世界去虚化（枚举 impl Trait for T）
- [ ] 闭包按分配点建模
- [ ] 验收：输入→struct→跨 3 层→sink 可追踪

## Phase M5：上下文敏感 + 污点 DSL
- [ ] 2-obj 上下文敏感
- [ ] source/sink/transfer/sanitizer JSON 配置
- [ ] 数据流规则全部配置化

## 上游机会（随时可做，独立于主线）
- [ ] 向 moonbit-compiler 提 PR：moonc build-package --dump-core-sexp（复用 dump_serialized_from_t）
