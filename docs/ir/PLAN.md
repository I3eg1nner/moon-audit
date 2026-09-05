# moon-audit IR 演进方案（v1，2026-09）

## 目标

在官方 parser 之上自建分析 IR（HIR），把 moon-audit 从 "AST lint + 文本摘要污点" 演进为
"类型化 HIR + 过程内流敏感污点 + bottom-up 函数摘要 + （可选）指针分析" 的 Tai-e 式引擎。
**部署哲学不变**：纯 MoonBit、无外部依赖、独立二进制、秒级扫描。

## 架构

```
.mbt 源码 ──► moonbitlang/parser AST（pin 0.3.18）
                 │  ★ AST 适配层（parser 隔离的是 **AST 形状变化**）。
                 │    修正（第三轮评审）：名字解析、脱糖、错误效应语义、
                 │    derive 生成行为、标准库约定（如 Map::get 经 Hash 再入用户代码）
                 │    仍与**语言版本耦合**——需版本化语义适配层承载，
                 │    并用官方编译器（moonc check）校验语义测试样例，
                 │    不能声明“parser 是唯一耦合点”。
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

## 里程碑与验收（2026-09-04 二次评审后重排）

> **口径撤回**：早前"M2 流敏感已超前 Tai-e"的表述撤回。流敏感只是精度的一个维度；
> Tai-e 的类型/堆/调用图/上下文建模提供其他维度，不可单项比较。
> 现状定位：AST 安全规则 + 局部类型重建 + 部分流敏感污点 + 单层摘要。
> 已知模型内反例（外部评审证实）：字段传播漏报、两轮循环传播漏报、
> `&Trait` 接收者解析失败、引入型 replace_all 曾被误判安全（已修复）。

重排路线（取代原 M2-M5 线性计划）：
1. 语义与指标修正 —— 错误清污修复（已完成 replace_all old/new 语义）、
   漏报反例检出、指标分母明确（"解析率"≠"调用图准确率"：具体类型≠方法已绑定）
2. 统一程序模型 —— .mbti 摄取（moonbitlang/parser 已含 mbti_parser/mbti_ast，
   可替代 builtin 硬编码表）、完整符号身份（包/类型/trait 身份，取消短名后缀匹配）、
   泛型替换、准确参数绑定、基础调用图
3. 显式 HIR/CFG + 摘要 —— 求值顺序、循环不动点、闭包环境、defer 退出路径、
   返回值/字段摘要、递归按 SCC 迭代；source/sink/transfer/sanitizer 配置化提前到此。
   **错误处理不是独立补丁阶段，而是本阶段完成标准的一部分**（第三轮评审）：
   前端完整性（默认参数/成功-错误分支/模式绑定/隐式调用进统一表示，暂不支持
   的结构明确报告，不得默认安全）+ 过程内正确性（出口明确、结构化值可投影、
   循环工作队列收敛、分支合并满足抽象域性质）+ 过程间可组合（正常/错误/堆/回调
   摘要统一参与递归求解，契约见 docs/ir/CONTRACTS.md）。
   **组合验收路径**：输入 → Result/错误载荷 → 模式解构 → 容器保存 → 闭包读取 →
   sink，必须告警；同时三个负对照必须不告警：① 读取另一安全分量（值结构投影）；
   ② 错误路径不可达（控制流）；③ 回调未执行（时机/逃逸）。只验证“能报出来”
   不够，必须验证“为什么不该报”。
4. 指针分析与调用图协同 —— 分配点堆抽象、字段敏感、增量工作队列
   （注意：MoonBit 有共享可变引用/容器/字段，不可用 Rust 式别名排除推理）
5. 上下文与规模优化 —— 比较调用点敏感/对象敏感/闭包环境敏感，不预设 2-obj

验收体系修正：
- "0 FP"不可单独验收：固定语料版本 + 修复前后样例，分别记录 TP/FP/FN/未知调用/未分析范围
- coverage 测的是分支覆盖≠调用图真值：动态调用边需额外插桩；未覆盖静态边不算 FP
- 缓存失效不能只靠源文件 hash：接口/目标后端/解析器版本/库模型/被调摘要均需入 key

## 原里程碑（历史记录，已被上面重排取代）（语料 = 本地 mocket + moon-audit 自身 + mooncakes 语料）

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
