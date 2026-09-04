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

## 待续（M4 起）
