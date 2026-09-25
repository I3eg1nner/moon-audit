# 第一条真实安全链：mocket HTML 响应

本目录分别保留真实 API 运行、官方声明绑定和受限源码到原生 IR 的实验验收。**它们不是生产语义模式的放行证明。** 分发工具运行不依赖这些 Python 开发脚本。

已固定 mocket `0.9.1`、提交 `af354b7a031ee8e0a7e62e76875b82a0a39ac71b`，使用已有依赖 async `0.21.0`、x `0.5.1`、mimetype `0.2.0`。运行前脚本将全部已跟踪源码与该 Git 提交逐文件比较，拒绝额外的未登记代码文件；不会升级或安装依赖。完整源码和依赖 SHA-256、编译器版本、命令、实际输出及诊断见 [机器证据](mocket-runtime-2026-09-25.json)。本次工具链是 moon `0.1.20260920` / moonc `v0.10.14+7d59c7ec9`，后端 native。

## 复现

准备该提交的 Git checkout 与已安装依赖的副本后执行；两个路径可相同。wrapper 设置对应 `MOON_HOME` 和 `PATH` 后原样执行收到的命令。

```sh
python3 experiments/security_chain/validate_mocket.py \
  --mocket /tmp/moon-audit-upgrade-20260922/compiled-corpus-mocket \
  --reference-checkout /data/my/corpus/oboard_mocket \
  --moon-wrapper /tmp/moon-audit-upgrade-20260922/with-toolchain \
  --output /tmp/mocket-runtime.json
```

脚本创建临时副本，将 [验收源码](mocket_chain_test.mbt.txt) 放入库的黑盒测试包，再执行 `moon test --frozen --target native mocket_chain_test.mbt --diagnostic-limit 3`。结束后清理临时副本。测试实际注册路由并调用 `dispatch_http`，由框架构造事件、查询解析、执行 handler、选择返回 responder、设置内容类型并序列化响应。

## 已通过的运行对照

8 个测试全部通过。查询 payload 为 URL 编码的 `<img src=x onerror=alert(1)>`，经 `event.req.query().get("q").unwrap_or("")` 和普通 String helper 传递。

| 场景 | 实际响应 |
| --- | --- |
| 原始输入进入 HTML 内容 | `<p><img src=x onerror=alert(1)></p>`，`text/html` |
| `escape_html` 后进入 HTML 文本位置 | `<p>&lt;img src=x onerror=alert(1)&gt;</p>`，`text/html` |
| `text` 响应 | `<img src=x onerror=alert(1)>`，`text/plain` |
| 常量响应 | `<p>constant</p>` |
| 危险 responder 构造后丢弃 | `<p>retained</p>` |
| 危险 responder 被常量 responder 覆盖 | `<p>replacement</p>` |
| 查询参数不存在 | `<p>missing</p>` |
| 编码后的 `alert(1)` 拼入脚本上下文 | `<script>alert(1)</script>` |

第八例证明 HTML 编码不能一概建模为“去污”。测试没有运行浏览器，也没有启动真实网络监听；结论仅为**真实 HTTP 派发路径将输入字节写入指定类型响应**，不宣称已经证明浏览器可利用 XSS，更不宣称库本身存在漏洞。这里验证的是使用原始 HTML API 时的应用数据流。

## 最小语义契约（生产放行条件）

- 声明身份：准确绑定 `Mocket::get`、`HttpRequest::query`、`Map::get`、`Option::unwrap_or`、`html`、`text`、`escape_html`，包括版本及依赖指纹；同名用户函数不能套用模型。
- 入口：框架对已注册 handler 参数的建模需可追溯；未注册函数不能被假定为外部输入入口。仅支持受限路由回调，不推导通用 async 调度或任意闭包。
- 值：顺序局部绑定/覆盖、已知 String 参数与返回、String 构造、只读事件和请求句柄、查询容器读取及 Option 缺省值。Map 写入/别名不在首批范围。
- 输出：区分创建 HTML responder 和将它作为路由返回值实际输出。丢弃或覆盖的 responder 不形成这条完整响应链。`html(&Show)` 仅对已确认 String 的实参建模。
- 净化：保留 HTML 文本上下文安全属性；脚本、URL、事件属性及无法确定的位置不能被 `escape_html` 清除风险。cmark 的安全 HTML 片段也不能与普通文本编码混为一谈。
- 未知：不支持的 helper、异常、非 String Show、容器修改或复杂回调必须保留未知影响并报告不完整，不能据此产生完整安全结论。

运行对照本身不能启用生产语义检测；下面单列声明绑定与原生核心实验，避免混淆证据等级。

## 官方绑定入口裁决（2026-09-25）

[绑定探针](validate_bindings.py)将 [非测试模板](binding_fixture/probe.mbt.txt)和[同名类型反例](binding_fixture/string_shadow.mbt.txt)复制到临时模块的两个包，先运行冻结依赖的定向 `moon check`，再查询官方 `moon ide peek-def/hover --json`。模板使用 `.txt` 后缀，避免根项目收集外部库验收包。

```sh
python3 experiments/security_chain/validate_bindings.py \
  --mocket /tmp/moon-audit-upgrade-20260922/compiled-corpus-mocket \
  --reference-checkout /data/my/corpus/oboard_mocket \
  --moon-wrapper /tmp/moon-audit-upgrade-20260922/with-toolchain \
  --output /tmp/mocket-bindings.json
```

[绑定机器记录](mocket-bindings-2026-09-25.json)保存原始 JSON、查询坐标、声明范围、目标源文件 SHA-256、声明源码行及每次查询耗时。当前全部必需声明都唯一匹配：

| 调用或访问 | 唯一声明 |
| --- | --- |
| `Mocket::get` | `index.mbt:152` |
| `MocketEvent.req` | `event.mbt:3` |
| `HttpRequest::query` | `request.mbt:33` |
| `Map::get` | 目标工具链 `builtin/linked_hash_map.mbt:269` |
| `Option::unwrap_or` | 目标工具链 `builtin/option.mbt:48` |
| `html` | `responder.mbt:92` |
| `escape_html` | `utils.mbt:128` |

定向 `moon check` 后直接 `--no-check` 查询曾报 `no metadata is available for any backend`。探针让首次官方 IDE 查询准备所需元数据，然后才进行 `--no-check` 查询。工具链版本、源文件和依赖快照不能在这两步之间变化。

**类型事实裁决：官方 hover 不能独立证明内建 String。** 合法的 `pub(all) struct String(Int) derive(Show)` 可作为 `html(&Show)` 的实参；该值与真正内建 String 的 hover JSON 都是 `contents: ["```moonbit\nString\n```"]`。二者编译均通过。因此“显式 String 注解 + 成功编译 + hover 显示 String”仍不足够。自定义 String 注解的 `peek-def` 指向本包类型声明，内建 String 注解没有可跳转定义；无定义结果不能作为自动认定内建类型的依据。

后续可在更窄的受支持子集中建立事实：从已绑定并指纹核实的 `HttpRequest::query` 返回原型出发，经已核实 Map/Option 操作与已检查的 String 构造、helper 函数体传播；不从任意 `String` 名称或 Markdown 文本推断规范类型。需要检查完整包作用域的同名类型/别名与输入原型；未知 `&Show` 或仅凭类型拼写的值应拒绝为该模型输入。通用规范 TypeId 和泛型实参出口仍未建立。

路由模板包含字面量路径、单个 `event` 回调参数和顺序语句，`get` 绑定与 `HttpHandler = async (MocketEvent) -> &Responder` 的固定模型共同确定入口。`peek-def` 对覆盖后的最终 `result` 仍返回最初 `let mut result` 的绑定位置，而不会返回最近一次赋值。这证明定义查询无法替代顺序 IR：必须处理覆盖、丢弃及最终返回的 responder，才能连接真实输出。

本轮结果是 `bindings_verified_type_boundary_restricted`：声明绑定门槛通过，通用类型出口未通过；这份绑定记录的查询坐标为人工指定。后续自动提取与原生 IR 证据见下一节，生产规则仍待放行。

## 受限源码到原生 IR（2026-09-25）

新增 `src/source_parser` 共享官方解析器与插值展开，`src/security_frontend` 提取源位置并查询官方声明，`src/security_ir` 独立解释有序值操作，`src/semantic_probe` 仅作开发入口。核心不依赖语法规则的告警或状态。

```sh
moon build --target native
python3 experiments/security_chain/validate_native.py \
  --mocket /tmp/moon-audit-upgrade-20260922/compiled-corpus-mocket \
  --toolchain /tmp/moon-audit-upgrade-20260922/toolchain \
  --output /tmp/native-ir.json
```

[原始记录](native-ir-2026-09-25.json)包含源码哈希、每次命令、编译器身份、自动绑定、IR、路径和耗时。脚本先核对固定库与依赖，再复制为独立消费项目；没有改库源码以适应编译器。完整 mocket checkout 的部分 examples/benchmarks 因旧 API 在当前编译器下失败，因此本实验只证明消费项目及其可达库依赖可编译。

13 项通过：原始查询、HTML 文本编码、丢弃、覆盖、纯文本、脚本上下文、同名 `escape_html` 普通函数、未知分支、递归预算、连续 30 次字符串翻倍，以及库变更、依赖变更、未支持注册形状。后面三个不能静默变成零告警成功。库与依赖使用完整目录指纹；聚合哈希明确采用字典序，不能使用 MoonBit String 的默认 shortlex 排序。

预算在数组/trace/路径分配前收费，默认 10000 个操作及展开单元、递归深度 64；前端最多 256 次声明查询，每次外部命令受进程监督。矩阵中 10 个回调需 102 次绑定查询，整次运行约 23 秒（本机首次记录）；这还不是大型项目性能验收，也没有完整的总内存硬限额。不能据此打开生产语义入口。

**结论范围：** 仅分析固定模型下 `.get(字面量路径, 单参数内联回调)` 的返回值。注册确实执行、middleware 不改写相关返回值/Content-Type 是前提；不证明注册可达性、任意动态派发或浏览器可利用性。显式静态注册调用尚未覆盖；零候选返回不完整。分支、异常、任意 Show、堆字段/别名和未知调用不做安全推断。报告始终带 `production_ready: false` 和 `coverage_status: restricted_experiment`；候选不完整或零候选退出 2。

下一门槛是独立复核反例、固定冷/热结果与峰值内存、减少逐调用启动 IDE 的成本、第二个真实库场景复用；然后才能决定是否做生产接入。不得把本实验称为完整的 MoonBit 安全分析框架。

独立 subagent 复跑同一验收脚本 13/13 通过（约 29.4 秒合计），确认本轮三个阻塞项关闭；[精简复核记录](../../docs/metrics/native-ir-independent-review-2026-09-25.json)保留各案例结论和范围限制。
