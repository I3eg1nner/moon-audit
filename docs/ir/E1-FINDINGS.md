# E1 (CFG 权威化) 执行记录与根因发现 — 2026-09-07

RESULT: BLOCKED（本轮未达 divergent=0；全部实验性改动已回滚，工作树恢复 72c09ae 全绿基线：301/301，run.sh 12/12）

## 已完成并验证的设计（可直接复用，均已回滚但代码路径在本文档+git stash 历史可复现）

1. `Stmt::CallStmt` 扩展 `loc~ : @basic.Location` + `recv_first~ : Bool`（10 处调用点全量适配，编译绿）
2. builder `emit_call` 重排：内层调用 temps 先分配（与 walk 分配序对齐）+ DotApply 补 receiver temp
3. 共享 finding 构造器 `emit_cwe113_header_finding`（walk 的 report_cwe113 委托之——单一 finding 语义）
4. 循环 widening 骨架：`apply_loop_widening`（写名收集 + heap 全字段污染 + widening-applied 计数）

## 核心发现：walk/builder 临时编号在方法调用形态下结构性错位（本轮真正的 blocker）

实测探针（SLOT 输出，`resp.set_header("X", val)`）：
```
[dbg] SLOT set_header [0:N 1:P 2:C]   ← 期望 [0:P(resp) 1:C("X") 2:P(val)]
[dbg] SLOT set_header [1:C 2:P 3:C]   ← 起始编号漂移（同函数多次分配）
```
walk 侧 DotApply 的 temp 布局 [recv, args...] 与 record_temp_taints_from(start=1) 的写入
存在一位错位——**recv temp 的污点记录落点与分配位不一致**（temp0=N 即 recv 污点未落在 0），
且起始编号在同函数内会漂移（前序 emission 未计入预期）。builder 侧即便完美对齐分配序，
exec 的 value slot 解引用（temps[2]）读到的是 Clean（"X"）而非 val 的 P。
这就是 D1b 时代 "AST 权威 + 对照" 模式没有暴露的深层问题：**两侧编号体系只在无嵌套、
无多调用的直线上函数巧合对齐**（mocket 94% cfg-executed 恰是此类），反例语料的 11 个
divergent 全部是布局错位受害者。

## 修复方向（下一轮 E1 的精确起点）

方案 A（推荐）：放弃"编号对齐"，改为**联合生成**——walk 在 hir_temps_from_pairs 时
把 temp id 写入 AST 侧调用点注释表（fn_name → [call_seq → temps]），builder 按调用序
消费同一表（build_block_ir 增参 walk_temp_table）。两侧零独立编号。
方案 B：exec 完全弃用 temp_facts，在块域内自求值（BindVar 状态域已具备），代价是复制求值语义（违背单一语义红线）。

## 回滚验证
git status 0；moon check --deny-warn 绿；301/301；run.sh GATE-OK（12/12，XFAIL=0 保持）。
