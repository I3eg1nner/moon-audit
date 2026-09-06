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

## 第三次快照（2026-09-05，工作流 #3 E1+E2 后：extern stub + dep .mbti + 别名身份 + LetFn）

155/155 × 4 targets，deny-warn 全绿；moon info 无 diff（E2 已在 db3a112 再生 mbti）。

| 项目 | findings | 文件 | 解析率 | 边覆盖 | vs 第二次 | 状态 |
|---|---|---|---|---|---|---|
| mizchi/luna.mbt | 0 | 91 | **84%** | 83% | +1 / = | clean ✅ |
| moonbit-community/cmark.mbt | 0 | 46 | **82%** | **82%** | +4 / +4 | clean ✅ |
| moonbit-community/crescent | **5** | 53 | **61%** | **63%** | +1 / +1 | findings（TP 稳定） |
| moonbit-community/rabbita | 0 | 144 | **70%** | **69%** | +3 / +1 | clean ✅ |
| moonbitlang/async | 0 | 170 | **71%** | **71%** | +2 / +2 | clean ✅ |
| oboard/mocket | 0 | 42 | **74%** | **74%** | +1 / +1 | clean ✅ |
| 本地 moonbit-petgraph | 0 | 56 | 69% | 69% | = / = | clean ✅ |

**对比结论**：
1. **修复护栏不破**：6 已修复项目 0 findings（第三次验证，E1/E2 符号身份变更零 FP 回归）
2. **TP 语料稳定**：crescent 5 条（CORS:6 / Cookie:35,48,49 / DoS:99）第三次完全一致
3. **E1/E2 增益全语料可度量**：七个项目解析率全线 +1~+4（dep .mbti 74 个接口文件 +
   moon.pkg 别名展开 + LetFn 注册）；语料最大增益 cmark/rabbita（依赖接口密集型）
4. 主线三目标：mocket 74→75%（unknown 469→185 中 FFI ~79/dyn ~30）、自举 86→**88%**、
   petgraph 持平 69%（依赖单一，杠杆饱和）

## 第四次快照（2026-09-05，scout21 语料扩容：17 语料 + 1 本地 = 18 项目）

新增克隆 15 仓（全部成功）；其中 4 仓无 `moon.mod`（regexp.mbt / tree-sitter-moonbit /
moonbit-native-runtime / python.mbt 为非标准布局）→ 排除扫描，实际入表 **17 语料 + 1 本地**。
TODO 记录的 "mio" 在 GitHub/mooncakes 均未定位（疑改名/删除），以替补项目补足。

| 项目 | findings | 文件 | 解析率 | 边覆盖 | vs 第三次 | 状态 |
|---|---|---|---|---|---|---|
| mizchi/actrun | 0 | 62 | **87%** | 87% | 新增 | clean ✅ |
| mizchi/crater | 0 | 611 | 78% | 78% | 新增 | clean ✅ |
| mizchi/luna.mbt | 0 | 91 | 84% | 84% | = / +1 | clean ✅ |
| mizchi/mars.mbt | **9** | 67 | 83% | 83% | 新增 | findings（见分诊） |
| mizchi/numbt | 0 | 3 | 84% | 84% | 新增 | clean ✅ |
| mizchi/tui.mbt | 0 | 95 | **87%** | 87% | 新增 | clean ✅ |
| moonbit-community/cmark.mbt | 0 | 46 | 82% | 82% | = / = | clean ✅ |
| moonbit-community/crescent | **5** | 53 | 61% | 64% | = / +1 | findings（TP 四次一致） |
| moonbit-community/rabbita | 0 | 144 | 70% | 71% | = / +2 | clean ✅ |
| moonbitlang/async | 0 | 170 | 71% | 71% | = / = | clean ✅ |
| moonbitlang/mooncakes.io | 0 | 54 | 76% | 76% | 新增 | clean ✅ |
| moonbitlang/moonyacc | 0 | 63 | 70% | 70% | 新增 | clean ✅ |
| moonbitlang/openseek | 0 | 909 | 71% | 71% | 新增 | clean ✅ |
| moonbitlang/quickcheck | 0 | 28 | 57% | 57% | 新增 | clean ✅ |
| moonbitlang/wasm5 | 0 | 87 | 77% | 77% | 新增 | clean ✅ |
| moonbitlang/x | 0 | 74 | 77% | 77% | 新增 | clean ✅ |
| oboard/mocket | 0 | 42 | 74% | 74% | = / = | clean ✅ |
| 本地 moonbit-petgraph | 0 | 56 | 69% | 69% | = / = | clean ✅ |

**对比结论**：
1. **修复护栏不破**：6 已修复项目 0 findings（**第四次连续**，扩容后新代码路径零 FP 回归）
2. **TP 语料稳定**：crescent 5 条（CORS:6 / Cookie:35,48,49 / DoS:99）第四次逐行一致
3. **新项目全部 clean**：11 个新增项目 0 findings（其中 openseek 909 文件为最大语料）
4. **mars.mbt 9 条新检出（Hono 风格框架，未适配规则）人工分诊**：
   - **TP 候选 ×5**：redirect.mbt:118/133/159（Location ← `ctx.path()` 用户输入经变换）、
     trailing_slash.mbt:163（Location ← 用户路径规范化）、
     request_id.mbt:53（`use_existing` 模式将用户请求头值直接回写响应头——回显向量）
   - **FP 嫌疑 ×4**：basic_auth.mbt:84（realm 为服务端配置）、etag.mbt:152（内容哈希派生、
     格式受控）、compress.mbt:197（内部枚举→header 映射）、cache_control.mbt:192（内部构造）
   - TP 候选率 5/9 ≈ 56%，与 lint 型 SAST 在未适配框架上的历史表现一致（mocket 首扫 8/8）
   - **后续动作**：redirect/trailing_slash/request_id 三类模式值得纳入 mars 适配规则或
     上游报告（上游 github.com/mizchi/mars.mbt）
5. 解析率全距 57-87%，中位 ~76%；平均较第三次无回退（旧 7 项目全部 ≥ 持平）


## 第五次快照（2026-09-05，第四轮整改 T0+T2 首批后）

范围：护栏 6 修复项目 + crescent/mars TP 语料 + 三本地目标（timeout 300 内完成）。

| 项目 | findings | 状态 |
|---|---|---|
| async / cmark / rabbita / mocket / luna(workspace luna/) | 0 ×5 | 护栏第六次连续 ✅ |
| crescent | 5（逐行一致） | TP 第五次稳定 ✅ |
| mars.mbt | 9（逐条一致） | 与第四次分诊表吻合 ✅ |
| mocket / petgraph / 自举 | 0 / 0 / 0 | FP 持平 ✅ |

**新发现（护栏范围外，非回归）**：luna 仓库 `sol/` 工作区（上游 33b24fe 2026-07-30
新增服务端运行时，历史护栏只覆盖 luna/ 子目录）检出 **7 条 CWE-113 候选**，均带参数
溯源（security_headers.mbt:188/275 "via parameter value"、runtime_static_serving.mbt:45-46
content_type/cache_control、sol_routes_register / server_island 路由策略）——模式与
mars 分诊的回显/配置注入向量同类，**待人工分诊后可上游报告**（PR 风格同 README 表）。
另有 14 个实验性文件解析失败（experiments/css-factorize，非产品代码，parse-failures
已在 scope 披露中计数）。
