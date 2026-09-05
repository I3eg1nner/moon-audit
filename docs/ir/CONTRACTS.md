# 分析内核契约（第三轮评审产物，2026-09-05）

> 评审结论：接近 Tai-e 的下一块实质成果是**能正确处理值结构、控制流和副作用的共享分析内核**，
> 而不是更多名义上完成的切片。本文件把该内核拆成两份显式契约，作为 HIR/CFG 阶段（原 M3）
> 的完成标准附件。每条标注当前状态：✅ 已实现（附测试锚点）/ 🔶 部分实现 / ⬜ 规划中。

## 契约一：值结构契约（Value-Structure Contract）

原则：MoonBit 大量使用 tuple / enum / Option / Result / struct / 容器 / 闭包，
**不能把所有值压成一个标量 Taint**——否则同时产生漏报（投影丢失）与误报（整体污染）。
每个值携带一个"污点形状"（taint shape），模式匹配按位置投影。

| 位置类别 | 投影语义 | 状态 | 锚点 |
|---|---|---|---|
| 元组分量 `.0/.1` | Tuple 模式 × Tuple 字面量右值**逐位绑定**；形状不匹配保守回退整体（过报不漏报） | ✅ | `v1_tuple_component_clean_no_report`（`(tainted, "safe")` 第二分量 Clean） |
| enum 载荷位置 | catch/Match 的 `Constr` 解构把（错误值/ scrutinee）污点投影到载荷变量；`Err(Bad(x))` 两层投影 | ✅ | `v1_error_payload_taint_reports`（错误载荷→header 告警） |
| struct 字段 | 对象级字段污点表（field_taint，A3 堆切片）；写入即污染对象槽位 | ✅ | A3 验收测试 `m4lite_source_to_object_cross_2_layers_to_sink` |
| 容器元素摘要位 | Map/Array 存入污点 → 容器摘要位污染；读取返回该位 | ⬜ M5（需字段敏感堆求解） | — |
| 闭包捕获槽位 | 捕获环境按槽位携带污点；逃逸分析区分立即/延迟执行 | ⬜ M5（依赖库模型 v2 的 timing 语义） | — |
| Match scrutinee 元组解构 | scrutinee 形状已知时逐分量绑定 | 🔶（保守整体绑定，方向为过报） | TODO 已挂 |

**抽象域性质要求**（HIR/CFG 完成标准）：分支合并必须满足 join 半格性质
（Clean ⊑ Tainted；join 幂等/交换/结合），循环以工作队列收敛到不动点。

## 契约二：函数效应契约（Function-Effect Contract）

原则：摘要不能只描述"参数→sink/返回值"。函数有**三类出口**，每类独立携带
返回关系与堆副作用——**抛错前已发生的堆修改不得丢弃**（第三轮评审红线）。

```
FuncEffect = {
  normal_exit : { return : TaintShape → ParamPositions   // 正常返回值关系
                , heap    : FieldWrites }                 // 正常路径堆更新
  error_exit  : { err_types : [Suberror...]               // 可达错误类型
                , payload  : TaintShape → ParamPositions   // 错误载荷关系
                , heap     : FieldWrites }                 // 错误路径堆更新（含抛错前副作用）
  callbacks   : [ { target : FnIdentity                   // 调用目标（lib 模型或闭包位点）
                  , args   : ParamPositions               // 实参来源
                  , timing : Immediate | Deferred         // 立即执行 vs 存储待推进
                  , escape : Captured | NotCaptured } ]   // 捕获/逃逸关系
}
```

| 条目 | 状态 | 说明 |
|---|---|---|
| 正常出口：返回值关系 | ✅（A1/p3sum `ret_from` 摘要） | 跨函数返回值传播已测 |
| 正常出口：堆更新 | ✅（A3 `field_taint` 摘要） | 对象级字段写传播 |
| 错误出口：Try fork/join + 载荷绑定 | ✅（V1） | 三出口状态合并，`err_t = body_t ∪ env_any_taint(body)`（保守近似） |
| 错误出口：错误类型区分 + 抛错前堆副作用保留 | 🔶 | 当前 err_t 不区分 Suberror 类型；堆副作用靠 catch 基环境=入口∪body后状态 近似保留——精确化在 HIR/CFG |
| 已知保守界（gate5 P2-b） | ⚠️ 记录在案 | `env_any_taint(body)` 并集计入**全部** TaintedParam 形参：函数有 ≥1 个形参、body 干净、错误载荷为常量时 catch 出口仍视为污点 → 方向为**过报不漏报**；三次语料快照 FP=0 实证未触发；HIR/CFG 阶段以"错误出口按位投影"消解，负对照测试锚点随之补入 |
| 回调：立即执行（`Array::map` raise?） | ✅（lib_callbacks 占位符回填即此语义） | 占位符 → 形参绑定 |
| 回调：延迟执行（`Iter::map` 存储待推进） | ⬜ M5 | 需 timing 字段（见 SCHEMA-v2）+ 逃逸分析 |
| 回调：trait 回调边（`Map::get` → 用户 Hash/Eq impl） | ⬜ M5 | 需闭世界 impl 索引产生调用边 |
| IRFn 参数化（函数类型带参数/返回/效应） | ⬜ M5 路线图 | 当前 `IRFn` 无参数信息；升级后闭包调用可携带效应摘要 |

## 组合验收路径（HIR/CFG 阶段完成标准，写入 PLAN）

> **正例**：输入 → `Result`/错误载荷 → 模式解构 → 容器保存 → 闭包读取 → sink。必须告警。
> **负对照 ×3**：① 读取另一个安全分量（值结构投影正确）；② 错误路径不可达（控制流正确）；
> ③ 回调从未执行（timing/逃逸正确）。只验证"能报出来"不够，必须验证**为什么不该报**。

## 库模型与内核的关系

库模型（见 `libmodels/SCHEMA-v2.md`）是效应契约在"不可见实现"上的实例化：
模型必须能**产生调用边与堆约束**，新增目标又能触发分析（Tai-e 式互驱动），
而不是把"官方库调用"当不产生调用边的黑盒——第三轮评审实证 `Map::get/set`
会经由用户 Hash/Eq impl 重新进入用户代码。
