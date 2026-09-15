# moon-audit → Tai-e 级转变计划

> 基线锚点（2026-09-08, `05ccc9a`）: 30,189 行 / 379 测试 / 190 commit / mocket 1489-1941 bound / ptB=10 / cfg 386/386(100%) / divergent=0 / FP 0/0/0 / crescent 5 TP
>
> 完成度判定基础: 六项四标准（详见 ROADMAP-T 终局表）

---

## P1: 动态调用真值闭环 [预计 2 周]

**目标**: 建立 "源码插桩 → 运行目标 → 静态/动态对比 → recall/precision" 的完整链路。这是从"框架骨架"到"有实证的分析工具"的分水岭，也是 Tai-e 论文 Table 1 的复现基础。

### P1.1 源码插桩器（3 天）
- `instrument` 子命令: 读取 ProgramWorld → 对每个已绑定调用点生成插桩桩代码 → 输出改写后的项目副本到 `<target>-instrumented/`
- 桩实现: MoonBit 侧 `instrument/runtime.mbt`——全局 `Array[String]` + 函数入口 `record("caller→callee@file:line")` + `main` 退出时写 JSON
- 不改语义: 插桩只添加调用，不改变控制流/数据流
- **验收**: 探针项目插桩后 `moon build && moon run` 产出 `calls.json`（含实际执行的调用点列表）

### P1.2 静态/动态对比器（2 天）
- `compare-calls <static-json> <dynamic-json>` 子命令
- 对齐: 按 (caller, callee) 边匹配; 报告三数——recall（动态边被静态覆盖的比率）/ precision（静态边在动态中观测到的比率）/ 未观测静态边清单（**不判为 FP**——可能是未执行路径）
- **验收**: 探针项目对比输出含 recall/precision/未观测清单; 设计文档（ACCEPTANCE.md）更新 "动态真值 ≠ 分支覆盖" 口径

### P1.3 语料实测（2 天）
- 对 3 个可运行语料项目（mocket examples / crescent / petgraph tests）执行全流程: 插桩→运行→对比
- 记录 recall/precision 到 `regression-baseline.md`——**这是 Tai-e 论文同款实验的最小复现**
- **验收**: ≥1 个项目的 recall 落档; 数字与 Tai-e 91.3% 参考对比（预期低于 Tai-e——诚实记录差距来源）

### P1.4 动态真值驱动的精度修复（3 天）
- 分析 recall 缺口: 哪些动态边未被静态覆盖（unresolved 的 ground truth 验证）
- 优先修复 top-3 形态（预期: FFI 库模型缺失 / 级联 / 高阶）
- **验收**: recall 数字在修复后可见提升; 修复形态落档

---

## P2: CFG 独立 Findings Producer [预计 1.5 周]

**目标**: CFG executor 完全独立求解并产生 findings；AST 仅用于明确披露的 fallback。这是评审持续的 "AST 仍是 producer" 问题的最终解决。

### P2.1 移除 temp_facts 依赖（3 天）
- block_exec 的 entry fact 从函数参数类型初始化（不继承 AST walk 的 temp_facts）
- 块内语句的转移函数独立计算（现有 `exec_stmt` 已具备，需切断对 walk 状态的读取）
- **验收**: block_exec 在纯 CFG 输入上产出与 AST walk 相同的 findings（12/12 反例）

### P2.2 权威切换完成（2 天）
- `run_flow_taint_func`: cfg_authoritative=true 时**只跑 CFG executor** 产 findings; AST walk 跳过（不再作为 safety net）
- ast-fallback 函数仍走 AST（披露不变）
- **验收**: 三目标 findings 与切换前逐条一致（12/12 反例 + FP 0 + crescent 5）

### P2.3 端到端精度对比（2 天）
- `--cfg-verify` 模式: 同时跑两条路径，输出逐函数对比表
- **验收**: 三目标 divergent=0 保持; 对比表落入 dump-analyses

---

## P3: 上下文敏感策略 [预计 2 周]

**目标**: 实现至少一种真实上下文策略并与 Insensitive 基线做对照实验。这是 Tai-e 论文的核心贡献方向。

### P3.1 CallSite(1) 实现（5 天）
- 上下文表示: 调用点字符串（`fn_name:line`）
- 过程间摘要: 按 (fn, context) 键缓存——不同上下文的同一函数有独立摘要
- 调用点: caller 的 context 传递给 callee 的摘要查询
- **验收**: 构造测试——同一函数被两个不同调用点调用，不同上下文下摘要不同（taint 状态可区分）

### P3.2 与 Insensitive 对照实验（3 天）
- `--context callsite-1` CLI flag
- 对 mocket/crescent 运行两种策略, 对比: findings 差异 / 摘要数量 / 运行时间
- **验收**: 差异分析落档（预期: callsite-1 更精确但更慢; 或在当前语料上无差异——也是有效结论）

### P3.3 ObjectSensitive(1) 探索（2 天）
- 接收者对象的 allocation-site 作为上下文
- 与 trait-param upper-bound propagation 联动
- **验收**: 构造测试通过; 或如实报告当前 pt 精度不足以支撑（依赖 P5）

---

## P4: Core/Async 库模型 [预计 2 周, 与 P3 并行]

**目标**: 覆盖 MoonBit 标准库和 async 的核心语义，消除 FFI/cascade 导致的 ~41% unresolved。

### P4.1 Core 容器模型（4 天）
- Array/Map/Ref/String 的效应模型: 元素约束（PTStore/PTLoad 已有）、迭代回调（immediate timing 已有）、方法返回类型（builtin 表降级后由模型接管）
- 每模型四类验证: 类型绑定 / 效应传播 / 调用边 / 正负例
- **验收**: mocket/petgraph 上 Array/Map 相关的 unknown 计数下降; 模型放置位置不影响行为

### P4.2 Async 语义模型（4 天）
- moonbitlang/async 的 HTTP 客户端/服务端、文件 IO、进程管理
- 框架回调: `spawn`/`channel`/`select` 的回调执行时机
- **验收**: 含 async 依赖的语料项目（mocket/async 本身）unresolved 下降

### P4.3 FFI 边界模型（2 天）
- `extern "C"` / `extern "js"` 的参数/返回类型传播 + taint 透传语义
- mongoose 模型扩展（已有基础上补齐剩余 ~79 个 unknown 位点的形态分析）
- **验收**: mocket FFI 文件（native/、js/）的 unknown 从 ~160 降到 <80

---

## P5: 过程间指针深度 [预计 1.5 周, 依赖 P3]

**目标**: 多层调用链上的对象流追踪，消除"只传一层"的限制。

### P5.1 Field-Sensitive 容器元素（3 天）
- Array 字面量 / Map 字面量的元素约束: `PTStore(container, "elem", value)` + `PTLoad(container, "elem")`
- 迭代回调: `each`/`map` 的元素读取产生 PTLoad
- **验收**: 构造测试: `let arr = [obj1, obj2]; for x in arr { x.act() }` → dispatch 目标含 Obj1::act 和 Obj2::act

### P5.2 闭包环境约束（2 天）
- capture var → closure allocation site 的约束（与 T2.5 captures 表对齐）
- 闭包调用时: 捕获变量的 pts 传入闭包体
- **验收**: 构造测试: 闭包捕获 struct 后调用其方法 → dispatch 精化

### P5.3 多层传播链（2 天）
- factory → ret → field store → field load → dispatch（跨 3+ 层调用）
- 当前 ≤2 轮反馈改单调 worklist（已在 E2a 做了, 验证多层链路可达性）
- **验收**: ROADMAP 评审组合路径 "input → Result 载荷 → 解构 → 容器 → 闭包 → sink" 端到端测试

---

## P6: 跨进程增量 + 性能工程 [预计 1 周]

**目标**: 从进程内缓存升级到跨进程持久化，建立性能基准。

### P6.1 磁盘缓存（3 天）
- 函数级摘要 + IR + 指向集以 JSON 序列化到 `.moon-audit-cache/`
- 缓存 key: `fn_hash + symbols_fingerprint + parser_version + analyzer_version`
- 增量失效: 函数体变 → 该函数+SCC 邻居重算; 符号表变 → 全失效
- **验收**: 同项目二次 scan 加速比 ≥2x（当前进程内已实现, 跨进程验证）

### P6.2 Release 性能基准（2 天）
- `moon build --target native` release 模式下的 timing 基准
- 记录: world-load / symbols / analysis / output 各阶段 ms
- 与冷启动对比; 与 Tai-e 32.8s（DaCapo）做参考对比（不同语料, 仅方向性）
- **验收**: 性能表落入 CONTEXT; 识别 top-3 瓶颈并优化

---

## 执行顺序与依赖

```
P1 动态真值 ──────────────────────────────────────────┐
P2 CFG producer ────┐                                │
                    ├──► P3 上下文敏感 ──► P5 过程间深度 ──► P6 性能
P4 库模型 ──────────┘                                │
                                                     ▼
                                              最终对标评估
```

- P1 与 P2/P4 可并行（无依赖）
- P3 依赖 P2（CFG producer 完成后上下文策略才有意义）
- P5 依赖 P3（上下文键是过程间传播的节点身份）
- P6 最后（所有功能稳定后做性能）

## 预计总工期: 6-8 周（单人全职）

---

## 最终对标判定标准（P6 完成后）

| 标准 | 测量方法 | Tai-e 参考值 | 目标 |
|---|---|---|---|
| 调用边 recall | P1.3 动态对比 | 91.3% | ≥80%（诚实起点） |
| 可达方法 recall | P1.3 | 95.9% | ≥85% |
| 调用图覆盖率 | ir-stats | — | ≥90%（当前 77%） |
| CFG 覆盖率 | analysis-scope | 100% | **100%**（已达成） |
| 上下文敏感收益 | P3.2 对照实验 | 论文报告 | 差异可测量（正/零/负均有效） |
| 过程间链路 | P5.3 端到端 | — | 组合路径测试通过 |
| 增量加速比 | P6.1 | — | ≥2x |
| 测试 | moon test --target all --deny-warn | — | ≥400 且全绿 |
| FP | 语料扫描 | — | 0（保持） |
| TP | 语料扫描 | — | crescent 5+ / mars 8+（保持或增） |

---

## 风险登记

| 风险 | 缓解 |
|---|---|
| 动态真值 recall 远低于预期 | 诚实记录——差距分析本身是有价值的产出 |
| CFG producer 切换后 findings 变化 | 逐条 diff + 反例保障；如有差异说明 CFG 语义更准确 |
| 上下文敏感在当前语料无差异 | 也是有效结论（语料可能不够大）；构造测试证明能力 |
| 库模型投入大但收益递减 | 按 unknown reason 分布优先投入（FFI 41% → async → core） |
| MoonBit 语言演化 | parser pin + moon.mod 版本声明 + CI 升级预警 |
