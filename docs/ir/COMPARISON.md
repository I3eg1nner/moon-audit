# 同类/跨品类工具对比（IR 层面视角）

## 定位光谱

```
AST lint ──── 摘要式数据流 ──── 指针分析 ──── 符号执行/验证
(Semgrep)   (Infer/SemgrepPro)  (Tai-e/CodeQL)  (KLEE/moonc prove)
     ▲ moon-audit 现在此处          ▲ 目标：M4 到这里
     └─ M2/M3 后到中间
```

## 逐工具对比

| 工具 | IR 层级 | 前端来源 | call graph | 污点分析 | 对我们的可抄点 |
|---|---|---|---|---|---|
| **Tai-e** (Java) | 自研 3 地址 IR（Jimple 血统）| Java 字节码（新前端 OOPSLA'25） | 指针分析 on-the-fly | 流不敏感、配置驱动（source/sink/transfer/sanitizer） | IR 指令集；污点配置 DSL；插件系统 |
| **go/ssa** (Go) | 官方 AST+types 之上的 SSA 库 | **官方 go/types**（关键差异：Go 官方给类型） | RTA + 保守闭包 | 无内置（x/tools 分析器自建） | **架构原型**：在官方前端上建 IR 供分析器消费，正是我们的处境 |
| **Infer** (Meta) | SIL（代数数据流 IR） | 各语言前端分离 | bottom-up 摘要（footprint） | 摘要式 | **M3 的样板**：跨过程=函数摘要组合，不做全局指针分析也够用 |
| **CodeQL** | 数据库化 AST+SSA | per-language extractor | 可配置 | 污点即查询（.ql） | 规则=查询的 DSL 设计（M5） |
| **Semgrep Pro** | AST + 轻量过程间数据流 | 模式匹配为主 | 有限 | 摘要式 | "精确够用即可"的产品哲学：不追完美指针分析 |
| **Soot** (Java 老前辈) | Jimple 3 地址码 | 字节码 | CHA/RTA/SPA | — | 3 地址码教科书设计 |
| **clippy/rustc MIR** (Rust) | MIR（borrowck 层） | 编译器内置 | — | — | 所有权语言 CFG 化的经验（match/借用的降级方式） |
| **starlint** (MoonBit) | 无 IR（AST lint） | moonbitlang/parser | 无 | 无 | 本地同类：质量向，无安全。互不冲突 |
| **moon-audit 现状** | 无 IR（AST 规则 + 文本摘要污点） | 同上 | 名字匹配（非真 call graph） | 文本式（taint_interprocedural.mbt: Phase1 逐行文本扫描） | — |

## 关键设计共识（跨工具验证过的结论）

1. **IR 必须与前端版本解耦**（go/ssa 靠 go/types 稳定接口；我们靠 AST→HIR 单一转换层）
2. **闭包是 call graph 第一难题**：Tai-e 用专门的 lambda 分析；go/ssa 用 RTA + 保守集。MoonBit 闭包按分配点建模即可起步
3. **污点分析不必流敏感也能用**（Tai-e 靠指针分析撑精度）：防过度工程，M2 的过程内流敏感已是加分项
4. **bottom-up 摘要是性价比之王**（Infer 十年验证）：M3 优先于 M4
5. **配置驱动的规则好过硬编码**（Tai-e/CodeQL 共识）：M5 让 source/sink 进 JSON

## MoonBit 特有的机会与陷阱

- 机会：闭世界（mooncakes 全源码）+ 显式 trait impl（`impl Trait for T` 可枚举）→ 去虚化可行率高于 Java
- 纠正（2026-09-04 评审）：MoonBit 存在共享可变引用/数组/结构体字段/闭包捕获，**不可**套用 Rust 式别名排除推理；堆模型必须覆盖 Ref、容器、可变字段
- 陷阱：泛型擦除（vtable 传参）→ 泛型函数体内方法调用是间接调用，需摘要化
- 陷阱：`extern "C"/"js"` FFI 黑盒 → taint 透传建模
- 陷阱：语言快速演化 → HIR 指令集保持小核心，语义外挂
