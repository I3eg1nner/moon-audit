# cmark 第二场景：运行行为与模型身份验收

固定 `moonbit-community/cmark 0.4.8` 提交 `ebf47ab9efcbd2ecff6f6ec8656c06a308395729`。仓库及上级目录未发现适用的 AGENTS.md。实验从该提交的 `git archive` 创建隔离副本，不修改库源码；固定依赖归档逐个匹配官方 registry SHA-256，清单见 [dependencies.json](dependencies.json)。

## 复现

```sh
python3 experiments/cmark_chain/validate.py \
  --cmark /data/my/corpus/moonbit-community_cmark.mbt \
  --archives /tmp/moon-audit-cmark-chain-20260925 \
  --toolchain /tmp/moon-audit-upgrade-20260922/toolchain \
  --output /tmp/cmark-model.json
```

首次缺少归档时加 `--download`，仅下载清单指定版本，不升级依赖。工具链 moon `0.1.20260920`、moonc `v0.10.14+7d59c7ec9`，后端 native。固定依赖：casefold `0.1.5`、charclass `0.1.4`、其传递依赖 ucd `0.5.0`、async `0.19.4`。库只检查 cmark_html 所需路径，consumer 检查整个消费项目，不据此声称所有库包/CLI均已通过。

[机器证据](cmark-model-2026-09-25.json)记录所有命令和诊断、原始绑定 JSON、声明坐标、源码与依赖文件指纹。结果：原库 `safe_default_test.mbt` **4/4**、独立消费项目 **7/7**、官方绑定 **4/4** 通过，库源码在原测试运行前后指纹一致。

| 对照 | 实际输出 |
| --- | --- |
| `render(safe=false, "<script>alert(1)</script>")` | 保留 script 标记 |
| 显式 `safe=true` | `<!--CommonMark HTML block omitted-->` |
| 省略 `safe` | 与显式 true 相同 |
| false 下 `javascript:` Markdown 链接 | 构造含 `javascript:` href 的 HTML |
| true 下同一链接 | href 清为空串 |
| 普通 `**hello**` | `<p><strong>hello</strong></p>`，不是编码文本 |
| 同名本地 `render(safe=false, ...)` | 身份指向消费项目，不能套用 cmark 模型 |

3 个真实库调用都唯一绑定到 `src/cmark_html/html.mbt:1032:8-1032:14`。同名负例唯一绑定到消费项目 `probe.mbt:17:4-17:10`。它们不是按短函数名区分的。

## 给核心的最小模型契约

仅登记固定声明 `moonbit-community/cmark/cmark_html::render`；模型需要库及实际编译依赖指纹、目标后端和参数布局。参数为一个 String 位置参数，`safe?=true`、`backend_blocks?=false`、`strict?=true` 三个标签参数，正常返回 String，且**可能 raise**。默认值只对核实的库快照成立；旧版本省略 safe 的含义不可沿用。首批 `safe` 只允许省略或 Bool 字面量；另两个标签仅允许省略或精确默认值。动态标志、其他 parser 配置必须显式拒绝/不完整。

建议增加一个独立 `RenderMarkdown(output, input, safe, site)` 操作，复用现有参数/返回、顺序值绑定、调用路径和最终 responder 输出计算。

- false 保留输入来源，生成可能包含 HTML 的输出；**清除之前的 HTML 文本编码凭据**。例如 HTML 编码并不改变 `[link](javascript:alert(1))`，Markdown 渲染却会把它变成危险链接，不能把这个操作当透明 transfer。
- true 的正常返回可登记经核实的 `SafeHtmlFragment` 属性，区别于 `EscapeHtmlText`。只有支持的 HTML 正文位置消费这一属性；脚本、属性、URL 或未知位置仍不完整。普通 Markdown 的 strong/p 标签正是区分两类值的运行证据。
- 显式强制终止型错误处理只有经过实际编译与语言语义核实后才可接入。任何未知 catch、恢复值或异常消费者不得凭正常返回模型忽略。当前实验只验证成功返回，未证明异常出口。
- `from_doc`、`renderer`、`xhtml_renderer` 涉及 Doc/Renderer 对象，不属于本模型；不以名称相似自动扩展。

现阶段通过的是第二个真实 API 的运行/绑定前置门槛，**还未证明 cmark 已通过生产前端进入共享 IR 或到达 mocket HTTP sink**。安全开关提示只说明已绑定配置；没有输入可控性与输出消费证据时，不能将其写成已证实 XSS。本目录不修改生产代码。

## 调用语法和异常终止复核

[callmode 机器证据](cmark-callmode-2026-09-25.json)纠正了先前尚未核实的 `render!` 设想：在已测 moon `0.1.20260920` 中，`@cmark_html.render!(...)` 被拒绝，报 E3002；它也不能令无 raise 函数/回调通过编译。

合法形式是 `try! @cmark_html.render(...)`。普通无 raise 函数与 `(String) -> String` 回调均通过编译，两个正常结果测试全部通过。官方 parser 输出为：

```text
Expr::TryOperator
  kind = TryOperatorKind::Exclamation
  body = Expr::Apply
    attr = ApplyAttr::NoAttr
```

所以不能将其实现为 Apply 的感叹号属性。前端第一步可只允许 `TryOperator(Exclamation)` 紧包已绑定的 `cmark_html.render`，其他 try/catch/try? 包装拒绝为不完整。正常出口使用渲染返回值；错误出口没有返回值。受控 raising helper 的实际执行打印 `BEFORE_TRY`，然后非零退出，未打印 `AFTER_TRY`，验证了该工具链的终止行为；这不表示本实验发现了会触发 cmark 异常的真实输入。

```sh
python3 experiments/cmark_chain/validate_callmode.py \
  --prepared-cmark /tmp/moon-audit-cmark-chain-20260925/cmark \
  --toolchain /tmp/moon-audit-upgrade-20260922/toolchain \
  --ast-exporter /data/my/moon-audit/_build/native/debug/build/src/frontend_export/frontend_export.exe \
  --output /tmp/cmark-callmode.json
```

该开发验收脚本在 Linux 使用资源限制关闭 core dump，生产工具没有 Python 依赖。此处未验证 Mocket handler 注册；后续统一生产入口仍需通过完整调用与返回路径验收。
