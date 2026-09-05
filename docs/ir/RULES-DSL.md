# Taint Rule DSL（源/汇/消毒器配置化）

> 评审指令（PLAN.md 第 2 阶段）："source/sink/transfer/sanitizer 的模型配置应提前，
> 避免继续把规则语义写死在求解器里。" 本 DSL 把流引擎的污点词汇表从代码迁到配置。

## 语义模型

**配置是增量（ADD），不是替换**：内置表永远生效，配置条目叠加其上。
无配置文件 = 与历史行为完全一致（156 条既有测试零改动的回归保障）。

## 文件位置（优先级从高到低）

1. `<项目根>/taint-rules.json` —— 专用文件
2. `<项目根>/.moon-audit.json` 的 `"taint"` 节

## 格式

```json
{
  "sources":    [{ "method": "fetch_input", "kind": "QueryParam" }],
  "sinks":      [{ "method": "custom_set", "kind": "HeaderValue", "value_slot": 1 }],
  "sanitizers": [{ "method": "cleanse" }]
}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `method` | ✅ | 方法名精确匹配（`recv.method(args)` 的 method 或自由函数名） |
| `kind` | — | 来源/汇的语义分类（诊断用；sink 仅支持 `"HeaderValue"`，其他 kind 暂不产生 CWE-113 告警，为后续规则预留） |
| `value_slot` | — | sink 专用：值实参的位置索引（默认 `1`，即 `set_header(name, value)` 的第二位）；labelled 实参 `value=` 恒被匹配 |

## 引擎接线点（src/taint_flow.mbt）

| 内置函数 | 配置扩展 |
|---|---|
| `classify_source_method`（query/param/body/header 提取） | `TaintRuleset::source_hit` 命中 → 结果 `Tainted` |
| `is_header_setter`（set_header/add_header/append_header） | `TaintRuleset::header_sink_hit`（kind 空或 HeaderValue） |
| `is_sanitize_call_name`（sanitize/escape/encode 子串） | `TaintRuleset::sanitizer_hit` 精确匹配 |
| `header_value_taint`（位置 1 / `value=` 标签） | `sink_value_slot` 覆盖位置索引 |

CRLF 剥离链判定（`replace_all` old/new 槽位语义）**暂不开放配置**——
它是安全语义修正的一部分（M2.6），配置化之前需要先积累对抗测试。

## 库模型（A2：extern 绑定与容器语义）

`taint-rules.json` 新增三个节 + 一个激活键（全部 ADD 语义）：

```json
{
  "extends": ["mongoose"],
  "types":     { "create_server": "Server" },
  "callbacks": { "Map::custom_each": ["K", "V"] },
  "sinks":     [{ "method": "mg_send", "kind": "Output", "value_slot": 1 }]
}
```

| 键 | 说明 |
|---|---|
| `extends` | 内置模型名（现内置 `mongoose`，见 docs/ir/libmodels/mongoose.json）；用户模型放 `<项目根>/libmodels/<name>.json`，优先于内置。未知名静默忽略 |
| `types` | 函数 → 返回类型表达式（`Server`、`Map[Int, String]`、`@pkg.Name`）——注册进符号表供 ir-stats/call-graph 解析 FFI 链 |
| `callbacks` | 高阶方法回调形参占位符：`K`/`V`/`E` 从接收者泛型实参解析，其余按类型表达式解析 |
| sink `kind: "Output"` | 输出通道 sink → **CWE-116/tainted-output**（新规则，默认开启；仅由模型/DSL 触发，无配置项目不受影响；`value_slot` 指定污点实参位） |

装载点：`run_ir_stats` Phase 1.7（types/callbacks → 符号表）；`scan_project`（taint 词汇表 → 流引擎）。
模型条目仅按方法名匹配——`extends` 是显式 opt-in，避免无 mongoose 项目被 `body`/`url` 等通用名误伤。

## CLI

```
moon-audit list-rules
  ...
  Taint rule vocabulary:
    source:      /path/taint-rules.json   （或 "built-in defaults"）
    custom entries: N (sources a, sinks b, sanitizers c)
```

扫描时 `scan_project` 从目标项目根加载一次，透传至 CWE-113 流引擎
（`run_cwe113(..., rules=...)` → `FlowCtx.taint_rules`）。

## 边界（如实记录）

- `kind` 除 `HeaderValue` 外的 sink 暂不告警（避免错误的 CWE 编号归类）
- 摘要收集（`collect_func_summaries_flow`）仍用内置分类——配置只影响规则扫描路径
- transfer 规则（参数间传播）尚未开放：当前引擎保守传播（任一实参污点即传播），
  显式 transfer 配置需要等显式 IR 后的精确数据流（PLAN 第 3 阶段）
