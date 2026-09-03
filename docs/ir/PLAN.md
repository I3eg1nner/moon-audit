# moon-audit IR 演进方案（v1，2026-09）

## 目标

在官方 parser 之上自建分析 IR（HIR），把 moon-audit 从 "AST lint + 文本摘要污点" 演进为
"类型化 HIR + 过程内流敏感污点 + bottom-up 函数摘要 + （可选）指针分析" 的 Tai-e 式引擎。
**部署哲学不变**：纯 MoonBit、无外部依赖、独立二进制、秒级扫描。

## 架构

```
.mbt 源码 ──► moonbitlang/parser AST（pin 0.3.18）
                 │  ★ 唯一的语言耦合点（parser 版本升级只改这层以下）
                 ▼
        M1 类型重建 → IRType（局部推断：签名标注 + 构造器 + 字面量传播）
                 ▼
        M2 HIR：FuncIr { sig, params, body : BlockIr }（3 地址化、match 降级、闭包显式）
                 ▼
        M2b CFG：BasicBlock + 前驱/后继（错误边、循环边）
                 ▼
        M3 过程内流敏感污点 + bottom-up FuncSummary（taint in/out/field-write/sink）
                 ▼
        M4 Andersen 指针分析 + 闭世界去虚化 call graph（分配点 = 堆抽象）
                 ▼
        M5 2-obj 上下文敏感 + 污点配置 DSL（source/sink/transfer/sanitizer → JSON）
```

设计红线：
- HIR 指令集以编译器 `core.ml`（MCore）为**规范参照**，但实现独立（不 parse Marshal）
- IR 按函数粒度缓存，key = 源文件内容 hash（复用现有 FNV-1a fingerprint 基建）
- 现有 14 条 CWE 规则中：数据流型（22/113/79/346）迁移到 HIR 引擎；配置型（614/942/770）留在 AST 层——**不为 IR 而 IR**
- LLM triage 永远是最后一级过滤器（差异化层，精度与 LLM 成本是乘法关系）
- 上游机会：向 moonbit-compiler 提 `--dump-core-sexp` PR（`dump_serialized_from_t` 现成），
  合入后未来可加可选的高保真 `.core` 摄取后端

## 里程碑与验收（语料 = 本地 mocket + moon-audit 自身 + mooncakes 语料）

| 阶段 | 内容 | 验收标准 | 预估 |
|---|---|---|---|
| M0 | 现状：AST lint + 文本摘要 | — | done |
| M1 | 类型重建 spike：调用点清单 + 解析率测量（`ir-stats` 子命令） | mocket 上方法调用接收者类型解析率 ≥60%（spike 门槛）/ ≥90%（M1 完成线） | 1-2 周 |
| M2 | HIR + CFG + 过程内流敏感污点 | guard 过滤从启发式变成数据流事实；CWE-113 在 mocket/async FP 不升 | 4-6 周 |
| M3 | bottom-up 摘要替换 taint_interprocedural.mbt | 跨 2 层调用的污点路径可追踪；对外 API 不变 | 3-4 周 |
| M4 | 指针分析 + 去虚化 call graph | "输入→存 struct→跨 3 层→sink" 路径可追踪 | 2-3 月 |
| M5 | 上下文敏感 + 污点 DSL | 数据流规则全部配置化 | ~2 月 |

每阶段收尾动作（强制）：`moon check` + `moon test` 全绿 → 跑 21 项目语料对比 FP/TP →
数字记入 CONTEXT.md → TODO.md 勾选 → 必要时修订本文件（反馈闭环）。

## 风险登记

| 风险 | 缓解 |
|---|---|
| 类型推断工作量超预期 | spike 先测量"解析率天花板"；不可解析调用走保守路径（不丢 finding） |
| parser 版本漂移 | pin 依赖；AST→HIR 单点隔离 |
| MoonBit 语义踩坑（闭包/trait 解析规则） | 以编译器 typer.ml 为参照实现；边界 case 写进 CONTEXT.md |
| 过度工程 | 红线：配置型规则不迁移；Tai-e 的污点本身流不敏感，M2 已超前 |
