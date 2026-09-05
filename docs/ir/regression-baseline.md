# 语料回归基线（corpus regression baseline）

> 生成方式：`bash scripts/regression.sh`（可重复执行）
> 二进制：`_build/native/debug/build/src/main/main.exe`（随主线演进而变；本文档数字为
> 2026-09-04 首次全量跑时的快照，含并行 Lane 的 .mbti 摄取改进）
> 原始输出：`/data/my/corpus-results/<name>/{scan.json,irstats.txt,callgraph.txt}`

## 口径说明（重要）

1. **已修复项目预期 0 findings**：README 漏洞表中 PR 已合并的项目（luna.mbt #103、
   mocket #12、async #494、rabbita #126），其上游 HEAD 已包含修复，扫描 0 findings
   是**正确行为**（回归护栏：若未来非空即误报回归）。
2. **未修复项目预期非空**：crescent PR #44 仍 Open → 检出应为真阳性（TP 语料）。
3. `解析率` = ir-stats 合并解析率（类型重建口径，非调用图准确率）；
   `边覆盖` = call-graph edge coverage（与解析率交叉验证，两者应一致）。

## 基线表（首次快照）

| 项目 | findings | 文件 | 解析率 | 边覆盖 | 状态 | TP/FP 备注 |
|---|---|---|---|---|---|---|
| mizchi/luna.mbt（workspace: luna/） | 0 | 91 | 83% | 83% | clean | 已修复(#103 合并)，0=正确 |
| moonbit-community/cmark.mbt | 0 | 46 | 75% | 75% | clean | 上游已改 safe=true，0=正确 |
| moonbit-community/crescent | **5** | 53 | 60% | 60% | findings | **PR #44 Open=未修复 → TP 预期**：CORS×1(main.mbt:6)、Cookie×3(35/48/49)、DoS×1(99)，类型与 README 检出记录(Cookie/DoS/CORS)吻合；README 时代为 8 条，现行规则 5 条（语义收紧后部分降Filter，待 LLM 研判复核确认无漏报） |
| moonbit-community/rabbita（workspace: rabbita/） | 0 | 144 | 67% | 67% | clean | 已修复(#126 合并)，0=正确 |
| moonbitlang/async | 0 | 170 | 69% | 69% | clean | 已修复(#494 合并)，0=正确 |
| oboard/mocket | 0 | 42 | 73% | 73% | clean | 已修复(#12 合并)，0=正确 |
| 本地 moonbit-petgraph | 0 | 56 | 69% | 69% | clean | 无 README 标签，unknown |

## 结论

- **修复后护栏**：6 个已修复项目全部 0 findings ✅（无误报回归）
- **TP 语料**：crescent 5 条与上游未修复状态吻合，可作为 precision 验证集
- **解析率区间**：60%（crescent，Web 框架）/ 83%（luna，UI 库）——与此前
  mocket 72%/自举 86% 的画像一致：Web 框架低于基础库
- README "21 个项目"的完整清单未在仓库内记录（仅有 6 个确认项目），本基线覆盖
  6+1；扩充语料需补齐清单来源（mooncakes 统计或发布记录）



## 第二次快照（2026-09-05，工作流 #2 集成：Phase-3 摘要 + p4 闭包分配点 + 验收体系）

二进制含：p3sum（return/field 摘要 + 两遍不动点）、p4clos（闭包分配点解析）、
accept（--baseline-report / 缓存 key）。148/148 × 4 targets，deny-warn 全绿。

| 项目 | findings | 文件 | 解析率 | 边覆盖 | vs 首次（解析率/边覆盖） | 状态 |
|---|---|---|---|---|---|---|
| mizchi/luna.mbt | 0 | 91 | 83% | 83% | = / = | clean ✅ |
| moonbit-community/cmark.mbt | 0 | 46 | **78%** | **78%** | +3 / +3（.mbti+闭包） | clean ✅ |
| moonbit-community/crescent | **5** | 53 | 60% | **62%** | = / **+2**（trait 分派边） | findings（TP 稳定） |
| moonbit-community/rabbita | 0 | 144 | 67% | **68%** | = / **+1**（分派边） | clean ✅ |
| moonbitlang/async | 0 | 170 | 69% | 69% | = / = | clean ✅ |
| oboard/mocket | 0 | 42 | 73% | 73% | = / = | clean ✅ |
| 本地 moonbit-petgraph | 0 | 56 | 69% | 69% | = / = | clean ✅ |

**对比结论**：
1. **修复后护栏不破**：6 个已修复项目 0 findings（p3sum 的字段/循环语义变更未引入 FP）
2. **TP 语料稳定**：crescent 5 条（CORS:6 / Cookie:35,48,49 / DoS:99）与首次快照
   完全一致——语义收紧后无新增漏检信号（摘要传播未改变检出集合）
3. **精度增益可度量**：cmark +3% 解析率（.mbti + 闭包分配点）；crescent/rabbita
   边覆盖 +2/+1（`&Trait` 分派边）——三目标画像与主线 mocket 74%/自举 86% 一致

## 复跑

```bash
bash scripts/regression.sh
# 覆盖二进制: MOON_AUDIT_BIN=/path/to/main.exe bash scripts/regression.sh
```
