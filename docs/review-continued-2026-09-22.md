# 2026-09-22 继续复核：尚未达到验收要求

## 结论与范围

复核对象是基于 `41f76dc5b0b6a796d4c7bb21fab3496111f3f9ae` 的当前未提交工作区。此前修复确有进展，但仍存在可编译程序上的漏报、误报，以及共享求解结果未进入实际消费者的问题，不能宣布完成 `suggest.md` 的语义验收。

本轮先修复了 `src/joint_points_test.mbt` 的测试编译问题：文件系统错误处理使用了不存在的方法，黑盒测试调用了非公开函数，集合断言还依赖了展示顺序。现在两个测试均经公开的 `unified_solve` 入口运行。没有将下列反例对应的分析语义改成“已修复”。

## 一、阻塞问题（按修复优先级）

### R1 / P1：方法字段副作用仍按裸方法名查找，真实调用漏报

位置：`src/taint_flow.mbt:3394`，同类遗漏在 `src/taint_flow.mbt:3353`。

`apply_ret_from_dot` 已使用接收者类型和规范目标；`apply_field_taint_side_effect_dot`、`apply_param_field_sinks_dot` 仍调用 `summary_lookup(ictx, mname, ...)`。定义表中的 `Box::put` 与裸名 `put` 无法匹配，后者直接返回，无副作用传播。

已编译反例 `method_field`：安全初始化 `box.value`，执行 `box.put(value)` 写入入口污点，再 `sink(box.value)`。应报第 8 行，AST、CFG 均无告警。仅把调用换成 `Box::put(box, value)`，两种模式都报告第 8 行。这个对照定位的是方法调用的摘要消费缺口。

**建议：**每个调用点只解析一次目标集合，返回关系、字段写入、字段 sink、传递 sink 共用该集合；逐目标合并效果，未知目标不能被当作无副作用。不要再为某一摘要通道另加裸名兼容查找。

**验收：**点调用与静态方法调用的告警一致；脏写入应报、安全写入不报；补充别名接收者、跨包方法和同名无关方法对照。

### R2 / P1：函数参数遮蔽全局函数时仍借用全局摘要，严格验证也放行

位置：`src/taint_flow.mbt:3041`、`src/cfg_value.mbt:63`。

`summary_lookup_qualified` 与 CFG 值降低都按表达式名字解析全局函数，没有先排除局部声明/函数参数的遮蔽。

已编译反例 `function_param_shadow`：全局 `pick(a,b)` 返回 `b`，而 `go` 的同名函数参数 `pick` 可以返回 `a`。`sink(pick(value, "safe"))` 应保守报告第 5 行；实际两个引擎均无告警，`--cfg-verify` 返回 0。联合指针核心已有局部遮蔽检查，但未覆盖上述生产消费路径。

**建议：**绑定阶段区分局部声明、参数、静态函数和未解析调用；摘要查询接收绑定结果，不再自行凭字符串推断。无法解析的函数值调用使用保守传播。

**验收：**参数名从 `callback` 改为 `pick`、新增/删除无关全局 `pick`，均不改变结果；同时覆盖 AST、CFG、SCC 和实际回调调用链。

### R3 / P1：返回摘要只能表达参数来源，丢失 callee 内部产生的污点

位置：`src/taint_flow.mbt:3872`、`:3930`；`src/taint_interprocedural.mbt:6`。

摘要收集只保存 `TaintedParam` 的返回关系。`wrapper() { source() }` 的无条件 source 返回没有被摘要表达，调用者退回实参污点合并；零实参合并为 Clean。

已编译反例 `source_return`：`sink(wrapper())` 应报第 4 行；AST、CFG 均无告警。CFG 能标记该返回值不受支持，但整函数回退后的 AST 仍漏报，因此“有回退原因”不等于保守性已经成立。

**建议：**增加明确的返回事实：已知安全、来自参数的集合、callee 内部 source、未知/不完整；将这些事实纳入 SCC 合并、收敛比较及缓存指纹。显式 `return` 和末尾表达式共用同一表示。

**验收：**无参 source 包装、多层包装、条件 source、递归返回都不漏报；常量返回、sanitizer 返回仍保持安全。

### R4 / P1：标签参数与位置参数混用时绑定错误，三个分析重复了同类逻辑

位置：`src/taint_flow.mbt:3242`、`src/cfg_value.mbt:106`、`src/joint_points.mbt:283`。

形式参数只保存名称，位置实参直接按完整参数数组下标绑定，未跳过标签参数。合法定义 `pick(first~ : String, second : String) { second }` 的两个对照：

| 调用 | 预期第 4 行告警 | AST | CFG |
| --- | --- | --- | --- |
| `pick(first="safe", value)` | 有 | 无（漏报） | 有 |
| `pick(first=value, "safe")` | 无 | 无 | 有（误报） |

CFG 第一行报告正确不能单独证明绑定正确：缺失的返回实参被默认视为污点，掩盖了同一个映射缺陷。两例严格验证均返回 2。

**建议：**保留形式参数种类、名字、位置序号、默认值信息，实现一份实参绑定函数，供污点、CFG 和联合指针约束共用。默认/可选参数必须按语言语义建模，缺失事实不能随意取 Clean。

**验收：**两个对照同时正确；再覆盖标签重排、标签简写、可选参数、默认值和带 receiver 的方法调用，并检查指针实参到形参的实际集合。

### R5 / P1：联合求解核心有真实反馈，但生产结果仍由多套路径分别生成

位置：`src/unified_solver.mbt:28`；`src/analysis_api.mbt:259`、`:302`、`:365`、`:373`。

- 新核心保留约束，新调用边增加实参/形参和返回值约束；两项核心测试已通过，这是有效进展。
- `unified_solve` 随后仍独立调用旧 `run_call_graph_with_world`，导出的图边取自旧路径，只替换 `pt_solutions`。新调用点目标没有直接成为图边的来源。
- 注册表 PointsTo 仍运行 `pt_world_summary`；CallGraph 将依赖结果转为字符串后丢弃，再另做一次联合求解。
- TaintFlow 将两个依赖结果转为字符串后 `ignore`，`scan_project_with_world` 没有收到这些事实。
- 回调在最终字符串边上重放，未发生在新约束进入工作队列时；注册表还硬编码 `pt_not_converged: false`，覆盖真实未收敛状态。

**建议：**PointsTo 生成一份类型化 `SolverState`；CallGraph 直接投影同一状态；TaintFlow 按 `CallSiteId` 消费同一目标和堆事实。移除字符串回读指标及重复求解。保留未解析、未支持、未收敛状态，在反馈循环中发布新增边事件。

**验收：**经过默认注册表检查精确目标、堆对象身份、最终告警与事件内容；临时断开共享结果传递后，测试必须失败。另加预算耗尽用例，确认公开图和 CLI 都披露未收敛。不要仅断言集合非空或执行顺序。

### R6 / P2：常量不可达分支仍告警，两个引擎一致并不能证明正确

位置：`src/block_ir.mbt:236`、`:292`。

已编译的 `if false { sink(value) }` 和 `while false { sink(value) }` 应均无告警；实际 AST、CFG 都报告第 4 行，严格验证均返回 0。CFG 无条件连接两个后继；当前生产 AST 路径也没有消除该告警。

**建议：**为常量条件实现可达性处理，保留条件求值自身的副作用；未知条件仍保守合并。把预期告警位置作为独立验收，不能只比较 AST 与 CFG 是否相等。

**验收：**两个 false 用例不报；true 分支/循环中可达的 sink 仍报告；加入条件中含 source/sink 的对照。

## 二、本轮验证证据

| 检查 | 当前结果 |
| --- | --- |
| `moon check --target all --deny-warn` | 通过 |
| `moon build --target native` | 通过 |
| `moon test --target native --deny-warn` | 428 / 428 通过 |
| `python3 scripts/cli_regression_test.py` | 37 / 37 通过 |
| Python harness unittest | 33 / 33 通过 |
| `bash tests/cases/run.sh` | 通过 |
| 新联合求解核心测试 | 2 / 2 通过，已包含在 native 总数内 |
| 新边界项目 | 8 / 8 编译通过；7 个场景至少有一种正常扫描模式违背预期；1 个静态方法对照正确 |
| `moon fmt --check` | 失败，退出 255；当前新增/修改文件尚未完成格式整理 |

全目标运行测试、固定真实语料重新验收、新边界的完整缓存生命周期，本轮未完成，不计为通过。`src/pkg.generated.mbti` 尚未同步新增公开接口，仍需 `moon info` 后复核。上述 native/CLI/harness 全绿只能证明已有测试未回归。

机器记录：[review-continued-2026-09-22.json](metrics/review-continued-2026-09-22.json)。原始检查日志在 `/tmp/moon-audit-review-current-*.log`；各反例源码、编译输出和 JSON 在 `/tmp/moon-audit-review-continued-20260922/`。

## 三、重放与下一轮交付

仓库保存了包含完整合法源码和预期告警行的[复核脚本](review-fixtures/2026-09-22/probe.py)：

```bash
moon build --target native
python3 docs/review-fixtures/2026-09-22/probe.py \
  /tmp/moon-audit-review-replay \
  _build/native/debug/build/src/main/main.exe
```

脚本逐项目先运行 `moon check`，再分别运行 AST、CFG、strict；保存完整输出。退出 1 表示 AST/CFG 与语义预期不符，退出 2 表示测试输入未通过编译。strict 输出用于诊断：回退尚未支持的语义允许明确失败，不能用它替代正确性断言。使用新的输出目录可避免旧缓存干扰。

建议拆成四个可独立验收的修复：

1. **调用绑定闭环：**统一局部遮蔽、方法目标及四类摘要消费；先关闭 R1、R2。
2. **实参映射与返回事实：**共享形参结构和绑定逻辑，补齐 source/unknown 返回摘要；关闭 R3、R4。
3. **生产共享结果：**完成 R5，再做断线验证、预算耗尽与事件反馈测试。未知对象/未支持表达式不得用空指向集合证明安全。
4. **控制流与收尾：**关闭 R6，整理格式及生成接口，然后重新跑全门禁、缓存和固定语料。独立 CFG 的未支持范围继续明确披露。

本轮完成的是继续复核和可重放证据，不是上述阻塞项的全部修复，也没有证明已达到 Tai-e 的能力水平。
