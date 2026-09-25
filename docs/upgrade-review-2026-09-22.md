# MoonBit 升级与生产路径复核（2026-09-22）

## 结论

**路线已调整：先验证独立核心，暂停现有 AST 能力扩张。** 本文记录旧流水线升级与修复；新核心的证据和迁移门禁以 [核心语义链架构验证](core-semantics-validation-2026-09-22.md) 为准。

**尚未整体达标。** 原始八个反例已经全部满足 AST/CFG 正常扫描的预期；联合求解结果已进入默认注册表、调用图投影和污点方法摘要消费。新版本 `errdefer` 的三个原始反例已修复，扩展 24 项合法场景通过；字节串 return 与插值语义修复已接入生产路径，async 快照编译和扫描通过；完整堆共享、全局身份闭环、上下文策略与真实语料语义验收仍未完成。

本记录对应基线 `41f76dc5b0b6a796d4c7bb21fab3496111f3f9ae` 上的未提交工作区；不能将其理解为已发布版本。旧失败基线保留在 [review-continued-2026-09-22.md](review-continued-2026-09-22.md)。当前机器记录见 [upgrade-review-2026-09-22.json](metrics/upgrade-review-2026-09-22.json)。

## 工具链与兼容性

| 项目 | 本次验证版本 |
| --- | --- |
| moon | `0.1.20260920 (914d7da)` |
| moonc | `v0.10.14+7d59c7ec9` |
| moonrun | `0.1.20260920` |
| parser / moon_config / lexer | `0.4.0` |
| x | `0.5.5` |
| quickcheck | `0.14.0` |

工具链从官方发布获取并校验归档 SHA256：`9226694de9ff978db1ecf820b7710c4224e84ec7a76b19a222d96f0cd4e31b6a`。安装目录为 `/tmp/moon-audit-upgrade-20260922/toolchain`；运行包装器为该目录上一级的 `with-toolchain`。本机默认的旧工具链没有被替换，复现时必须选择上述版本或兼容版本。

本次迁移修复显式黑盒测试导入、公开 trait 扩展方法、IterVisitor 调用及 parser AST 变更。旧 parser 0.3.18 在新编译器下出现标签参数语法错误；不能只升级编译器而保持旧前端依赖。版本背景见 [MoonBit 2026-09-21 更新](https://www.moonbitlang.com/updates/2026/09/21/index)。

`moon fmt`、`moon info` 已执行；生成接口已同步。新增语法被 parser 接受，不等于安全分析已具备相应语义。

## 生产链路已接入的部分

1. PointsTo runner 生成一份 `SolverState`；CallGraph runner 使用该状态中的调用图；TaintFlow runner 将同一状态传给扫描器。
2. `project_call_graph` 读取共享调用目标和指针类型，不再调用旧的 `pt_solve_batched`。外部符号与未覆盖语法仍使用类型推断回退；该回退中的源函数身份仍需统一。
3. 污点的点调用返回、字段写入及字段 sink 路径，通过公共目标查询消费共享目标。缓存指纹包含所消费的目标集合。
4. 调用点使用起止偏移，区分 `make()` 与 `make().step()` 这类共享起点的嵌套调用；allocation ID 仍独立保持原构造位置。
5. 新边事件在连接实际参数/返回约束时发出，同一 caller/callee 去重。预算耗尽保留 `converged=false` 并传递到调用图。
6. 公开入口的外部参数、未知调用返回和字段传播保留不完整性。只有完整且收敛的接收者集合允许裁剪类型候选；污点查询保守合并本地类型候选。

### 接线证据

`src/joint_points_test.mbt` 的七项测试覆盖真实反馈、跨调用堆对象身份、标签/默认参数、嵌套调用、预算耗尽、默认注册表污点消费和部分接收者。

其中工厂方法测试必须在默认注册表产生第 6 行告警；随后清空同一共享状态的目标集合再次扫描，告警消失。这证明测试覆盖了消费连接，并检查热缓存不会继续返回旧结果。真实 CLI 另有可编译的脏/安全工厂方法对照。

这还不能证明污点与指针共用完整堆：污点环境仍维护独立 heap/sites，完整字段与别名传播是后续工作。

## 原始八个反例的复核

| 项目 | AST / CFG 预期位置 | strict 结果 |
| --- | --- | --- |
| method_field | `[8]` / `[8]` | 2，字段效果尚需整函数回退 |
| static_field | `[8]` / `[8]` | 2，字段效果尚需整函数回退 |
| source_return | `[4]` / `[4]` | 0 |
| function_param_shadow | `[5]` / `[5]` | 2，间接调用尚未支持独立 CFG |
| constant_branch | `[]` / `[]` | 0 |
| constant_loop | `[]` / `[]` | 0 |
| labelled_safe | `[]` / `[]` | 0 |
| labelled_first | `[4]` / `[4]` | 0 |

上述项目全部通过新编译器检查。strict 返回 2 是对未支持语义的披露，不能把这些项目记作独立 CFG 已支持。

## 门禁发现并修复的回归

函数遮蔽修复最初使 cases 中六个场景漏报：函数参数 `sink` / `emit` 被判为局部调用后，显式 DSL 模型也被屏蔽。修复现在区分显式模型与同名全局定义：用户配置的 source/sink 仍生效，局部回调不会借用全局函数摘要或内置 sanitizer 假设。

cases 门禁已恢复全部通过。新增真实 CLI 测试同时检查模型 source 和 sink 都是回调参数的情况。

## 异常语义修复与补充复核

原先五项中失败的被调函数抛错、内部 catch 消费和异常发生时状态三个反例已经关闭。[upgrade_probe.py](review-fixtures/2026-09-22/upgrade_probe.py) 现包含 24 个独立可编译项目，AST/CFG 正常扫描均满足精确告警位置。

实现与证据：

- 异常退出保留类型、payload 和退出时环境/堆；catch 消费可确定匹配的异常，未知类型保留可能分支。构造器身份包含包路径，类型通配匹配使用所属 suberror。
- 调用和方法摘要传播错误返回及正常返回能力；SCC 签名与缓存依赖同时包含两种事实。CLI 分别修改错误摘要、正常返回能力，验证热缓存结果随之改变。
- defer/errdefer 在对应退出状态执行，保留注册时词法绑定；覆盖嵌套清理、变量遮蔽、return 时清理抛错、已捕获异常和递归调用。
- noraise 回调不生成异常退出；类型化回调保留所属错误类型，包括含多个构造器的类型。
- 新补充的 for/for-in 用例暴露了零次迭代路径被抛错循环体覆盖的漏报；现保留这条正常路径，并增加必执行抛错循环的不可达对照。
- 跨包同名异常测试又定位到旧 moon.pkg 行扫描器：它漏读单行 import，且显式别名仍注册默认别名。现在导入路径与别名均从官方 moon_config AST 提取，并检查单行/多行布局一致性。

这只证明已列场景：完整循环 else、break/continue 状态与清理、外部函数错误效果仍待系统验收。独立 CFG 尚未执行异常语义；含异常摘要的调用明确触发整函数回退。四项 strict 抽查均返回 2，不能将正常 CFG 模式的通过记作独立 CFG 完成。

## 验证记录

- 全目标类型检查、全目标构建、格式检查和生成接口同步已通过。
- CLI：61/61；harness：33/33；cases：通过。
- 原始八项反例：8/8 编译且符合语义预期；扩展异常语料：24/24 编译并符合 AST/CFG 正常扫描预期。
- 默认参数修复后四后端完整测试通过：wasm、wasm-gc、JS、native 各 **437/437**。各后端测试串行执行，避免固定临时目录相互干扰。
- 最新扫描器对三个固定真实语料副本完成了清空函数缓存后的冷扫描和随后热扫描，告警及错误集合均一致；内容哈希及每文件哈希已保存。mocket、crescent 原快照包含历史未提交改动，不能只用 Git revision 标识其内容。

| 固定快照 | 文件数 | 告警 | 解析诊断 | 退出码 |
| --- | --- | --- | --- | --- |
| mocket | 42 | 0 | 0 | 0 |
| crescent | 53 | 5 | 0 | 0 |
| async | 170 | 0 | 0 | 0 |

### 前端修复及缓存迁移

`return b""` 的最小程序通过新编译器检查，但 Handrolled 会报错并丢失 return 的值；MoonYacc 能保留正确 Bytes 常量。对 async 的 `src/fs/file.mbt`，两者均提取 39 个顶层项，原始诊断分别为 1 / 0。

现在所有生产解析调用都进入 `parse_source`：Handrolled 成功时使用其 AST；它报错时只有 MoonYacc 无诊断才采用备用结果；两者都失败时保留原诊断。三项前端单测验证字节返回值、原文件/行号、错误诊断保留及主解析器的正常语法。

语义复核又发现：两个官方顶层 parser 都把插值中的表达式保留为原始文本。原实现对字节插值直接返回 Clean，对普通字符串插值则猜测变量名，导致安全局部变量误报、内部 sink 调用漏报。前端现在通过官方 lexer / 表达式 parser 按原坐标递归展开插值，供符号、摘要、污点、调用图、HIR/CFG 共用。

CLI 新增三组合法/非法对照，覆盖字节返回的跨函数摘要与冷/热缓存，字节/字符串插值的脏安全值、内部调用、嵌套插值、非法插值表达式。简单插值通过 strict CFG，复杂语句仍按既有能力边界回退。

策略版本为 `handrolled-moonyacc-interpolation-v2`，纳入分析键和函数缓存键。使用升级前保存的扫描器与当前扫描器对同一合法程序顺序执行：三个共同函数的缓存指纹全部变化；随后热缓存完全稳定。没有通过修改测试源来触发这次缓存失效。

async 的 170 个文件现无解析错误，冷/热扫描均退出 0；独立 `moon check --target native --frozen` 也通过。这证明编译与解析兼容，不能据零告警断言完整异步语义或漏洞检测能力已经验收。

mocket 前一轮两处告警都经过 `sanitize_header_value` 后再调用 `to_cbytes`；源码确认 sanitizer 过滤 CR/LF。本轮补齐编码与泛型格式化摘要后两处误报消失，固定快照冷/热扫描均为零告警。crescent 五项告警位于既有 e2e 测试服务器，不能直接推断生产部署风险。

### 完整编译验收的边界

- async 原固定快照通过新编译器检查。
- mocket 与 crescent 首次离线检查缺少依赖；随后在独立副本安装声明版本，保留原始扫描快照。
- mocket 全模块检查有三处 `@strconv.from_str` 缺失，位于两个 benchmark 和一个 example，均在默认扫描排除范围内；`moon check native/mongoose --target native --frozen` 及其依赖通过。
- crescent 全模块检查有两处 `lexscan` 输入类型不再被新编译器接受，位于 `cookie/cookie.mbt:137,176`。固定源码未被改写。

前端修复阶段，补齐依赖后的两个副本也完成冷/热扫描，mocket / crescent 分别为 2 / 5 条告警；该历史结果与依赖集合 SHA256 保留。当前转换修复的三份固定原快照结果见上表。

因此，完整编译结果已查明；仍需为最终语义验收选择可编译的固定版本，不能把外部快照版本问题算作分析器漏报，也不能忽略它们后宣称全语料验收通过。

### 转换修复及新增剩余反例

[conversion_probe.py](review-fixtures/2026-09-22/conversion_probe.py) 扩展为 **20 个合法项目，AST/普通 CFG 全部通过**。修复包括规范包身份下的 UTF-8 返回关系、泛型 Show 的延迟实例化、Logger 写入效果、多层/方法包装及延迟 sink；摘要稳定签名和缓存指纹包含新增事实。跨包同名类型和跨文件实现“安全→source→安全”的缓存回归通过。

独立 CFG 尚未支持接收类型相关返回和写入/sink 效果：泛型 Show 两项 strict 抽查返回 2，简单 UTF-8 包装返回 0。普通 CFG 的通过包含整函数 AST 回退。

同时新增 [remaining_probe.py](review-fixtures/2026-09-22/remaining_probe.py)：七项均编译成功；默认阶段关闭默认依赖、默认 sink 效果、安全字面量别名三项；当前继续关闭字段内部 source、接收者别名、多来源字段三项，只剩普通泛型 trait 失败。前两项此前 strict 错误返回 0，现在返回 2 并保留正确结果，明确独立 CFG 尚未执行默认表达式。

精确行号、修复入口与优先级见 [suggest.md](../suggest.md) 的“七项反例复核”。当前仍不能宣称整体达标，也不能将 core Show 的专门模型当作所有泛型派发已完成。

### 默认实参与类型事实

新增 [default_probe.py](review-fixtures/2026-09-22/default_probe.py) 的 **22 项合法项目通过**。默认表达式按调用处实参绑定，在被调方词法作用域中依次执行一次；显式覆盖/转发 Some 跳过、None 执行，未知存在性合并。返回、写入、sink、异常使用同一绑定。异常状态保留抛错时堆，sink 定位到触发默认值的调用点。

跨包同名 helper、跨包泛型 Show、默认表达式从安全变为返回 source/触发 sink 再恢复安全的热缓存回归通过。规范类型事实随局部绑定、赋值和分支传播，修复工厂返回和多层包装的泛型默认值漏报，也关闭了安全字符串局部别名误报。

当前独立 CFG 对执行默认表达式的调用整函数回退，strict 返回 2；全部显式覆盖的简单对照 strict 返回 0。这是明确的当前边界，不应将 22 项普通 CFG 通过记作独立 CFG 完成。

默认阶段新增独立污点语义策略 `call-defaults-and-type-facts-v1`，参与缓存指纹并进入 scope。使用策略变更前后实际二进制复核，在符号代次不变时三个已有函数缓存指纹全部改变，新策略热缓存稳定。递归默认表达式展开上限为 16；耗尽时保守保留未知值/异常并披露 `default-argument-expansion-exhausted`，合法递归测试已验证。耗尽计数非零意味着仍有默认效果未展开，不能作为完整语义验收通过。

### 字段事实、出口状态与新边界

当前字段摘要保存完整 `SecurityFact`，根据参数对象身份归并别名；正常/提前返回的堆后置条件与异常出口分开收集、实例化。clean 覆盖、多个来源、内部 source、getter 字段投影、分支无写路径、同名声明遮蔽、复制与交换均有合法正反例。构造 allocation ID 格式与联合指针侧一致，仍各自维护 heap/sites，未宣称完整堆共享。

[field_probe.py](review-fixtures/2026-09-22/field_probe.py) 共 **23 项可编译项目，21 项 AST/普通 CFG 通过**；strict 均返回 2。当前失败项：

- `two_formals_alias_read_after_write`：预期 `[8, 9]`，实际 `[8]`，同一对象经另一形参读取刚写入的值时漏报。
- `two_formals_alias_clean_last`：预期 `[]`，实际 `[8]`，同一对象后写清理产生误报。

完整字段探针保持退出 1。CLI 新增门禁只检查已关闭 21 项，保留两项开放反例的正确预期而不锁定错误输出；**61/61 不能表示字段 23/23**。下一步必须保留字段读写顺序或按实际别名分组实例化，不能只合并形参最终字段值。

冻结前最终污点策略为 `bounded-field-exit-facts-v2`，正常/异常字段事实进入 SCC 签名和缓存指纹。跨包同名 Box/get/fill 的“安全→正常出口 source→异常出口 source→安全”冷/热扫描通过，证明缓存消费者接入新事实。原始 8、异常 24、转换 20、默认 22 项用同一新二进制重跑，仍全部符合 AST/普通 CFG 精确行号预期；remaining_probe 为 6/7。

### 冻结前的性能收尾

旧字段补丁的递归符号路径导致 crescent/async 在 180 秒内超时。冻结前加入可披露的来源宽度 64、字段深度 4 限制，超限保留未知污点，scope 包含 `summary-fact-widened`。最终固定快照冷/热扫描恢复：mocket 约 4.7/4.7 秒、crescent 6.0/5.9 秒、async 22.2/21.6 秒，告警仍为 0/5/0，错误集合为空且冷/热一致。

最终旧流水线四后端各 437/437，CLI 61/61，harness 33/33、cases 通过；新策略前后实际二进制的三个已有缓存指纹均变化，热缓存稳定。预算计数和未收敛仍需关注，性能收尾不代表旧核心已达标；后续已转为独立核心验证。

日志目录：`/tmp/moon-audit-upgrade-20260922/`。终态结果以机器记录为准。

### 可重放命令

```bash
# 先确保 PATH/MOON_HOME 选择上表工具链
moon check --target all --deny-warn
moon build --target all
moon test --target all --deny-warn
moon fmt --check
moon info
python3 scripts/cli_regression_test.py
python3 tests/harness/test_harnesses.py
bash tests/cases/run.sh
python3 docs/review-fixtures/2026-09-22/probe.py /tmp/review-boundaries _build/native/debug/build/src/main/main.exe
python3 docs/review-fixtures/2026-09-22/upgrade_probe.py /tmp/review-upgrade _build/native/debug/build/src/main/main.exe
```

最后一条当前应退出 0；返回 2 表示生成项目不能编译，返回 1 表示告警位置不符合语义预期。`conversion_probe.py OUTPUT_DIR ANALYZER` 当前应退出 0；`remaining_probe.py OUTPUT_DIR ANALYZER` 当前退出 1，保留七项反例，其中四项仍待修复。

默认参数专项可重放：`python3 docs/review-fixtures/2026-09-22/default_probe.py OUTPUT_DIR ANALYZER`，当前应退出 0。
