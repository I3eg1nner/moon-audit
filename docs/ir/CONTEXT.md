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

## 待续（M2 起）
