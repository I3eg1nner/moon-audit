# MoonBit 基础设施与 Tai-e 核心取舍复核（2026-09-22）

## 结论与路线决策

**建议将目标收缩为：固定分析器构建工具链、独立验证目标项目的 MoonBit 版本，支持明确语言子集、能够解释跨函数污点路径的安全分析器。Tai-e 用作组件设计参照，不再作为整体功能或跨语言性能的验收对象。**

先解决“编译器能够交付哪些可靠语义事实”，再决定核心实现。此前安排的全堆快照优化应排在前端可行性之后。Python 核心原型保留为语义对照；当前 AST 扫描器、已验证规则和语料继续保留，但都不证明新路线已成功。

本轮完成了官方资料核查、公开编译器源码版本核对，以及一个合法 MoonBit 包上的 CLI/IDE 实测。没有实现新前端、编译 compiler fork 或重新验收生产分析器。原始命令、输出、探针源码和版本见 [机器记录](metrics/moonbit-infrastructure-2026-09-22.json)。

## 1. 重新核实后，哪些基础设施可用

| 基础设施 | 本轮证据 | 对项目的决定 |
| --- | --- | --- |
| `moon` 构建与包管理 | 最小包 `moon check` 成功；`moon build --dry-run` 输出真实 `moonc build-package` 命令，含依赖 `.mi`、包身份、目标后端和源码目录 | 复用项目构建上下文，避免从 import 文本另建一套依赖解析。dry-run 文本本身不是稳定机器协议，适配需固定版本。 |
| 官方 parser / lexer | 项目已使用 0.4.0；提供语法解析入口 | 保留源码位置和语法结构用途，不把 parser 当作类型检查器。 |
| `moon ide` | 实测 JSON 能提供局部变量类型、直接调用定义位置及局部变量引用 | 可用于绑定/类型对照，以及受限适配可行性实验。尚不是完整语义前端。 |
| `moon ide analyze` | 官方定义为公开 API 使用次数统计 | 不能将其名称理解成污点分析或完整调用图导出。 |
| `moonc` 当前发行版 | 本机固定为 v0.10.14+7d59c7ec9；`build-package/check/link-core -help` 未列出 TAST/MCore 的结构化导出选项 | 当前没有验证到可直接消费的带类型 IR 导出契约；这不是对全部隐藏选项或内部 API 不存在的证明。 |
| 公开 OCaml 编译器源码 | GitHub API 查询 `main` 为 `d4ada10d212b5376f7f8bf49cd2fbaa275a395df`，提交时间 2025-09-29；本地旧源码的 driver 与远端相同 | 不能视为当前 2026-09 工具链的配套源码。旧 dump 补丁不能直接列作新版落地方案。其他公开分支仅登记，未证明与发行版匹配。 |
| `.core` / `.mi` | 旧源码有内部序列化格式；新版小包也生成二进制产物 | 不直接用旧 OCaml 类型布局读取新版文件；相同文件魔数不证明 schema 或运行时兼容。 |
| LLVM / Wasm 后端产物 | 当前 help 列出 LLVM IR 和 WAT 输出入口 | 可作后端专用分析候选；未实测其对 MoonBit 源码身份、字符串、错误和模型映射的保真度，暂不选作通用源码审计入口。 |
| MoonLLVM / MoonMIR / MiniMoonBit | 官方 MoonLLVM README 将其定位为 IR 构造和后端基础设施，MiniMoonBit 是语言子集前端 | 可参考实现方式，不能当作当前完整 MoonBit 的现成类型前端或 IR 提取器。 |

资料：[Moon 构建系统](https://github.com/moonbitlang/moon)、[官方 parser](https://github.com/moonbitlang/parser)、[MoonBit Agent IDE](https://docs.moonbitlang.com/en/latest/toolchain/moonide/index.html)、[公开 compiler 源码](https://github.com/moonbitlang/moonbit-compiler)、[MoonLLVM](https://github.com/moonbitlang/MoonLLVM)。表中本机版本及输出以机器记录为准；nightly 文档不能替代固定版本验证。

### 已实际验证的语义查询

探针中的两个形参接收同一个对象，函数内先写 `dirty`，再写 `safe`：

```moonbit
pub struct Box { mut value : String }
fn fill(first : Box, second : Box) -> Unit {
  first.value = "dirty"
  second.value = "safe"
}
pub fn go() -> String {
  let box = Box::{value: "initial"}
  fill(box, box)
  box.value
}
```

- `moon check`：退出 0。
- `moon ide hover --loc probe.mbt:8:8 --json`：返回 `Box`；类型在 Markdown `contents` 中，并非规范 TypeId。
- `moon ide peek-def --loc probe.mbt:8:3 --json`：返回第 2 行 `fill` 的定义位置。
- `moon ide find-references --loc probe.mbt:7:7 --json`：返回两个实参位置和最后的字段读取位置。
- `moonc build-package ... -g -O0 -dsource`：退出 0、stdout/stderr 为空，产出二进制 `.core/.mi`；本探针没有得到文本语义导出。

这证明官方工具已经能回答部分语义问题，**未证明**它能输出实际调用目标集合、默认参数求值、泛型约束实例化、错误出口、闭包捕获或 CFG。不能用定义位置查询代替动态调用图。逐位置启动查询还可能带来成本，批量能力和全项目性能需要单独测量。

### 公开源码可以怎样使用

在已核实的旧提交中，`typedtree.ml → core_of_tast.ml → core.ml` 提供了类型检查后及降低后的表示；`core_format.ml` 有 S 表达式打印函数。它们适合研究前端边界，不能证明当前发行版已经提供外部接口。[固定版本源码](https://github.com/moonbitlang/moonbit-compiler/tree/d4ada10d212b5376f7f8bf49cd2fbaa275a395df/src)

候选导出层优先考虑 **带类型 AST 或优化前 Core**。这是工程判断：前者更接近源码，后者更便于保留显式求值顺序；最终应由实际样本验证源码位置、调用绑定和错误降低是否完整，而非先选名字。即使导出完整类型，动态调用、堆别名和库效果仍需分析。

此外，源码采用 MoonBit Public Source License v1，不能按宽松许可证依赖处理。官方对编译器修改的说明有限制，fork 复用方式需按其条款核实；本轮没有复制 compiler 实现或建立分发方案。[官方许可证](https://www.moonbitlang.com/licenses/moonbit-public-source-license-v1)、[compiler README](https://github.com/moonbitlang/moonbit-compiler#license)

## 2. 从 Tai-e 选择什么

参照固定版本 **Tai-e 0.5.4**；`current` 文档已显示 0.5.5-SNAPSHOT，不混用其新增能力作为本项目要求。

| 选择 | 参考组件 / 机制 | 本项目最小实现与验收 |
| --- | --- | --- |
| 必选：规范程序表示 | Tai-e `IR / Stmt / Var`、统一程序信息 | 自有小 IR，只保存经验证的函数/变量/字段身份、位置、调用绑定与顺序指令；各分析共享同一事实来源。 |
| 必选：数据流与不动点 | CFG、数据流求解；`DefaultSolver / WorkList` 的增量通知思路 | 工作项对应基本块及必要调用输入；事实变化只通知依赖者。递归域有界、预算状态可见。无需先实现通用插件平台。 |
| 必选：对象与字段抽象 | `HeapModel / Obj / InstanceField` | 分配点对象、别名、字段读写；同一模型贯穿参数、返回、正常/异常出口。明确何时可覆盖，何时只能合并。 |
| 必选：安全模型与结果 | source / sink / transfer / sanitizer 配置 | 首批一个 CWE 的真实路径；模型按规范 API 身份匹配；结果给出来源、调用链、位置和不完整原因。 |
| 按需求加入：指针与调用图反馈 | `Solver / Plugin` 的新指向关系、新调用边通知 | 第一版只接受已解析直接调用；接入间接调用时再引入共同求解，不能在外围各自猜目标。 |
| 暂缓 | 多种上下文策略、Zipper/Scaler/Mahjong、泛化插件注册、生产增量缓存 | 只有真实反例或性能数据证明必要时再做。上下文策略固定一种；对象区分是否足够由工厂/别名反例裁决。 |
| 不作为目标 | JVM 类初始化、反射、invokedynamic、Android、Spring 等适配 | 这些服务于 Java/Android 生态，不纳入 MoonBit 达标清单。 |

依据：[Tai-e 程序抽象](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/program-abstraction.html)、[分析与依赖](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/develop-new-analysis.html)、[指针分析框架](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/pointer-analysis-framework.html)、[污点配置](https://tai-e.pascal-lab.net/docs/0.5.4/reference/en/taint-analysis.html)。上表是本项目的取舍建议，不是 Tai-e 的能力限制。

### 不能直接抽一个 PTA 求解器，就期待解决现有顺序问题

检查 0.5.4 `DefaultSolver`：指向关系通过差集增长传播，实例字段读写添加指针流边；核心依赖 `World / ClassHierarchy / TypeSystem / JMethod / JField`。因此，直接抽取 Java 实现仍需大量语言适配，并非接上 MoonBit AST 即可使用。[固定版本求解器](https://github.com/pascal-lab/Tai-e/blob/v0.5.4/src/main/java/pascal/taie/analysis/pta/core/solver/DefaultSolver.java)

更关键的是，字段上的这种流不敏感传播不保存“这次读取之前最后一次写入”的堆版本。它能帮助回答别名问题，但本项目要求后写清理、异常出口区分，还要保留顺序敏感的状态传递。原型中已经正确表达的 Load/Store 顺序应该保留。Tai-e 官方教学材料也明确解释了忽略字段读写顺序的精度损失；教学简化不等于整个生产框架的能力上限。[官方别名数据流例子](https://tai-e.pascal-lab.net/en/pa7.html)

同样，Tai-e 求解器达到时间限制时会警告结果可能不健全；不能从“有 time-limit 选项”推导出“预算耗尽自动保守”。我们应继续坚持未知效果和不完整状态的显式契约。这是本项目的选择，不要求全盘照搬 Tai-e。

## 3. 为什么此前投入难以变成可靠能力

1. **同时重建语言前端和分析框架。** parser 能识别语法，但默认参数、trait、错误降低、方法绑定等需要语言语义。摘要消费者不断补猜，维护成本跟随语言更新增长。
2. **入口可用性没有先验收。** 旧研究把未编译的约 20 行 dump 补丁当作低成本后路，没有先证明源码版本、发行版匹配及外部数据契约。
3. **验收对象不断扩大。** 测试数量、接口接线、AST/CFG 输出相等不能证明同源状态已统一；两个消费者也可能共享同一种错误。
4. **借鉴粒度过大。** 整体对齐 Tai-e 混入 Java 生态特性与框架产品化工程，挤占了最重要的污点链正确性验证。
5. **过早锁定部署形式。** 为保持独立二进制而自己重建类型，未证明其总成本更低。建议允许依赖固定工具链；仍需衡量安装和版本维护成本。

前三项有项目证据：旧 [IR 研究](ir/RESEARCH.md)、[上游补丁草稿](ir/upstream/README.md)、[字段/升级复核](upgrade-review-2026-09-22.md) 与 [原型限制](core-semantics-validation-2026-09-22.md)。后两项是基于这些证据的路线判断。

## 4. 下一阶段：先做有停止条件的入口实验

以下是建议执行顺序与预算，不是已经完成或保证工期。

### G0：语义入口裁决，最多 3 个工作日

交付一份 `frontend-contract` 和可复现探针产物，必须逐项回答：

- 使用哪个工具链、哪个后端、怎样获得包和源码清单；是否要求被分析项目通过 `moon check`。
- 函数、变量、字段、调用目标、实参对应关系、源码位置分别来自哪里；外部名字不能冒充稳定 ID。
- 实际导出格式、schema/版本指纹和错误处理；升级不兼容时显式拒绝。
- 当前发行版是否有可批量消费的语义接口；若只能用 IDE 查询，测量逐位置/批量成本并确认返回内容能支撑限定子集。
- 若尝试 compiler 导出，必须先证明源码与发行版/依赖兼容，再编译、运行；不能直接套用旧补丁。需要上游能力时先形成具体接口需求，等待上游不能成为无限延期的理由。

优先验证官方工具入口；源码改造只作为版本匹配后的候选。两者都不能形成可靠契约时，结束本轮核心扩张，选择明确有限的 AST 规则/局部分析产品，并记录跨函数能力缺口。不要自动切回“自行实现完整类型系统”。

### G1：只贯通一个真实安全链

建议先选现有 **CWE-113 HTTP 头部注入**，完成“输入 → helper → 可变字段 → helper/返回 → header sink”，同时包含安全常量和净化对照。第一版面向可检查通过的固定后端项目，支持直接调用、字符串、局部绑定、分支、结构体字段、返回，以及经入口验证的正常/异常控制流。

复用合法反例，至少列清以下必测项：

1. 同一对象传给两个形参，先写后读。
2. 同一对象后写清理，反转写入顺序的对照。
3. 两个不同对象与局部别名/变量遮蔽。
4. 跨包同名函数和字段，绑定不串包。
5. 返回对象与调用者共享对象身份。
6. 正常出口与错误出口上的字段状态不混合。
7. 递归收敛和预算耗尽。
8. source/sink 同名普通函数不误匹配，真正净化后的安全对照不误报。

泛型 trait、默认参数、闭包、async/FFI 暂不作为第一版支持能力；分别设置至少一个边界探针，要求明确不完整或拒绝，绝不能静默按安全处理。旧 generic_trait 和其他未关闭问题保留登记，不能因缩小支持范围改成“已修复”。

**验收须从真实 `.mbt` 自动进入新 IR 和新核心**，不能手写 IR 替代前端验收。输出需包含可检查的绑定和 Load/Store 顺序；仍需旧 AST 污点、第二套堆或例子专用分支时，判失败。

### G2：有了真实输入，再优化和裁决迁移

- 对 G1 的相同 IR 做状态存储/哈希优化，使用现有具体执行器与别名/异常见证防止改变语义。
- 固定 mocket、crescent、async 快照，先统计每个入口及其可达函数的已支持/未支持范围。只接入一小部分时，只能报告局部覆盖，不能把整项目零告警算通过。
- 建议初始资源门槛：同一机器、每项目 60 秒硬上限及 1 GiB 峰值内存，包含前端；先声明门槛，再运行三次报告中位耗时和峰值。此数值是待验证的项目预算，不是 Tai-e 对标结果。
- 已声明支持的安全链及依赖应完整覆盖；人工标注正/负对照均满足预期，预算未耗尽，诊断位置正确，才允许迁移该范围。
- 生产增量缓存另设后续验收；第一版可以无缓存。未来加入时验证冷/热结果及策略升级失效。

不再用 Tai-e 在 Java/DaCapo 上的耗时、调用边比例作为 MoonBit 的通过阈值。真实执行观测可发现漏边，但没执行到的静态边不能直接算误报。

## 最终意见

这次收缩的重点是减少自行承担的语言语义和框架范围。**下一项交付应是“当前 MoonBit 语义入口可用性裁决”，随后才是“一条真实安全链闭环”。** 如果入口条件不足，交付边界清晰的有限分析器也比继续承诺完整框架更可控。
