# 库模型 Schema v2（草案，2026-09-05）

> 第三轮评审实证：`Array::map` 在调用期间执行回调（签名 `raise?`，回调抛错影响外层）；
> `Iter::map` 只存储回调、推进迭代器时才执行（`core/builtin/iterator.mbt:361`）；
> `Map::get/set` 会调用键的 `Hash` 并在查找中用 `Eq`——**官方库调用可能重新进入用户代码**。
> 因此"官方库调用"不能统一当作不产生调用边的黑盒；模型必须区分回调时机与再入边。

## 回调三分类

| 类别 | 语义 | 实例 | 引擎处理 |
|---|---|---|---|
| **Immediate** 即时回调 | 调用期间执行；回调抛错按错误多态传播到外层 | `Array::map/filter/sort_by`（`raise?`） | ✅ 现行 `callbacks` 占位符回填即此语义（形参污点绑定） |
| **Deferred** 延迟回调 | 存储回调，后续推进才执行；捕获环境逃逸 | `Iter::map` | ⬜ M5：需逃逸/推进建模（当前若作 immediate 处理，方向为过报） |
| **Trait 回调边** | 库经 trait 方法再入用户实现 | `Map::get/set → hash/eq`、排序比较器 | ⬜ M5：闭世界 impl 索引产生调用边（与去虚化共用索引） |

## v2 字段（引擎已实现最小读取路径；完整求解标注 M5）

```jsonc
{
  "name": "example-model",
  "types":     { "create_thing": "Thing" },          // v1：返回类型注入
  "sources":   [ { "method": "read_input", "kind": "RequestData" } ],
  "sinks":     [ { "method": "emit", "kind": "Output", "value_slot": 1 } ],
  "callbacks": {
    // v1 形式（等价 immediate，向后兼容）：
    "Array::map": ["T"],
    // v2 对象形式：
    "Iter::map": { "slots": ["T"], "timing": "deferred" }
  },
  "trait_edges": [
    { "method": "Map::get",  "trait_method": "hash", "note": "lookup calls key Hash/Eq impls" }
  ]
}
```

- `timing`：`"immediate"`（默认）/ `"deferred"`。解析入 `TaintRuleset.cb_timing`；
  M5 效应求解器消费（延迟回调的污点只在推进点进入）。
- `trait_edges[].{method, trait_method, note}`：声明再入边，解析入
  `TaintRuleset.trait_edges`；M5 与 impl 索引联立产生调用边。
- **未知行为保守近似声明**：模型未覆盖的库函数一律按"可能调用任意用户代码 +
  可能污染返回值"的保守近似处理，且分析报告中列出未建模的调用点（HIR/CFG 阶段
  完成标准：**暂不支持的结构明确报告，不能默认为安全**）。

## 引擎侧现状（本草案的落地边界）

- `TaintRuleset` 新增 `cb_timing : Array[(String, CallbackTiming)]` 与
  `trait_edges : Array[TraitCallbackEdge]`（`src/taint_rules.mbt`），
  解析路径支持 v1 数组与 v2 对象双形式（向后兼容，无配置=行为不变）。
- `size()` 计入 v2 字段（纯 v2 模型不再被当作空规则集丢弃）。
- 求解侧**未接线**（诚实边界）：timing/再入边当前不影响告警，M5 效应求解器
  （`docs/ir/CONTRACTS.md` 契约二 callbacks 节）统一消费。

## 对齐 Tai-e 的要点

Tai-e 指针分析框架中**调用图与指针分析互驱动**、新对象/新调用边可通知插件
（`PointerAnalysis` 提供 `addPlugin` / `getCallGraph` 等扩展面）。我们的对应物：
库模型产生调用边与堆约束 → 触发分析扩展 → 新目标再入分析。仅枚举 trait 实现
（现行 CHA）不够——模型边要参与不动点。
