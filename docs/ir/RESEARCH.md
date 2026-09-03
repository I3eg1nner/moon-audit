# 官方 IR 调研结论（2026-09 调研，事实以当期源码为准）

## 结论速览

| 问题 | 答案 |
|---|---|
| 官方有公开的 IR 规范文档吗？ | **没有**。moonbit-docs（★2402）全库无 IR/MCore 章节 |
| 编译器源码开源吗？ | **开源**：`moonbitlang/moonbit-compiler`（OCaml，★705，MoonBit Public Source License v1） |
| IR 叫什么、定义在哪？ | **MCore**，`src/core.ml`（4,854 行）+ `mcore.ml`（4,893 行） |
| 有 IR 文本 dump 工具吗？ | **库里有、CLI 没暴露**：`core_format.ml` 的 `dump_serialized_from_t`（.core → S 表达式）存在但无任何调用方 |
| `.core`/`.mi` 文件格式？ | 魔数（`MCORE240123`/`MINTF230520`）+ **OCaml `Marshal`** 二进制序列化 |
| 能直接消费 `.core` 吗？ | 理论可以（需实现 Marshal 读取器），**不推荐**：payload 结构 = OCaml 类型布局，随编译器版本漂移，脆弱 |

## 编译器管线（源码实证）

```
parsing_*.ml ──► typer.ml/typedtree.ml (TAST, 10,866 行)
                    │ core_of_tast.ml (2,170 行, MCore 化)
                    ▼
              core.ml / mcore.ml  ← MCore IR（我们的目标层级）
                    │
        ┌───────────┼─────────────┐
        ▼           ▼             ▼
  wasm_of_clam_gc  clam_of_core  core_link/core_dce
  (wasm 后端)     (lambda 级)    (.core 链接/DCE)
```

## MCore 指令集（core.ml `expr`，安全分析视角标注）

| 指令 | 语义 | 对分析的价值 |
|---|---|---|
| `Cexpr_var { ty; ty_args_; prim }` | 变量引用，**带完整类型** | 类型重建免费 |
| `Cexpr_as { trait; obj_type }` | **trait 对象上行转换** | 动态分派点显式化 |
| `Cexpr_apply { func: var; args; prim }` | 调用，**func 是具体 var** | call graph 基本现成 |
| `Cexpr_letfn / Cexpr_function / Cexpr_letrec` | 局部函数/闭包（Nonrec/Rec/Tail_join） | 闭包建模素材 |
| `Cexpr_constr { tag; args; ty }` | 构造（分配点） | 堆抽象的 allocation site |
| `Cexpr_record / Cexpr_field / Cexpr_mutate` | 结构体读写 | field-sensitive 基础 |
| `Cexpr_switch_constr / _constant` | match 已降级 | CFG 构建简化 |
| `Cexpr_loop / break / continue` | 循环（带参数的尾递归形式） | CFG 循环边 |
| `Cexpr_handle_error` + `return_kind` | 错误效应处理 | 异常边显式 |
| `Cexpr_assign` | 可变变量赋值 | 流敏感需求来源 |

`.core`（`core_format.ml::serialized`）单文件包含：program(IR) + **types(Typedecl_info)** + **traits(Trait_decl)** + **methods(方法表/vtable)** + ext_methods + pkg_name——即每包自带全量类型/trait 元数据。

## 序列化细节（决定性约束）

```ocaml
let export ... = output_string oc magic_str; Marshal.to_channel oc [| serialized |] []
```

- OCaml `Marshal` 与 OCaml 运行时/编译器版本耦合，无跨语言稳定性承诺
- **判决**：直接解析 `.core` = 把 moon-audit 的命运绑在 OCaml 内部布局上，PASS
- 但 `dump_serialized_from_t`（sexp）是现成的 → **上游 PR 机会**：给 `moonc build-package` 加 `--dump-core-sexp` 标志（约 20 行 OCaml），官方 README 明言"开源编译器出于安全目的"，此类 PR 合理且可能被接受

## moon CLI（moonbitlang/moon，Rust，开源）

纯构建编排，不含 IR 处理逻辑；`moon build` 逐包调用 `moonc build-package` 产出 `.core`。`moonc` 的 CLI 选项（`-help` 实测 + 源码 driver_config.ml）中与 IR 相关的只有 LLVM 后端的 `-S`/`-emit-llvm-ir`（LLVM IR，非 MCore）。

## 其他排查过的官方仓库

- `moonbit-docs`：无 IR 文档（仅 package-manage-tour.md 一处无关命中）
- `moonbit-RFCs`：无 IR 相关 RFC（语言特性向）
- `moonbit-agent-guide`：404/default branch 缺失
- `parser`（★35）：官方 AST 解析器 = moon-audit 现用前端，AST 带源码级标注类型、无解析后类型
- `tree-sitter-moonbit`、`moonbit-tmLanguage`：编辑器语法层，无类型
- mooncakes registry：无任何 IR/分析类包（前轮已全量扫描 2,328 包确认）

## 对 moon-audit 的战略含义

1. **自建 IR（AST→HIR）是主路线**：与 moon-audit"无外部依赖独立二进制"的部署哲学一致，且不依赖编译器内部
2. **MCore 是规范参照物**：自建 HIR 的指令集设计以 core.ml 为蓝本（它已经解决了 match 降级、闭包表示、错误边等问题），降低语义踩坑
3. **上游 PR 是低成本的"高保真模式"入场券**：若 `--dump-core-sexp` 被合入，未来可加可选的 `.core` 摄取后端，获得 100% 精度类型/分派信息（Marshal→sexp 后格式仍随版本变，需 pin）
4. **类型重建仍是主路线的核心成本**：M1 的局部推断不可回避，但 MoonBit 顶层签名显式标注 + TAST 结构可参照（typer.ml 即官方推断算法的参考实现）
