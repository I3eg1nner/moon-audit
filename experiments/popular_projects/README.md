# 热门 MoonBit 项目检查（2026-09-25）

后续[可用性优化与固定快照重测](optimization-2026-09-25/README.md)已解除 core/actrun 文档链接阻断，并校正 native 选源；仍保留 literate 格式不完整状态。下文统计保留原始实验口径。

## 结果与范围

已检查 **Mooncakes 官方下载榜前 12 个发布版本 + GitHub stars 前 12 个仓库固定提交**。24 个样本中，23 个导入成功；15 个完成请求的语法范围、8 个不完整，1 个因归档外部符号链接未导入。已导入样本选择 4,653 个文件、解析 4,562 个，91 个未解析。**默认规则 2 条发现；显式启用全部 14 条规则共 447 条语法线索。这不是漏洞统计。**

下载榜来源为 [Mooncakes 首页 Most downloaded](https://mooncakes.io)，页面没有暴露各包下载量和统计时间窗，记录排名而不编造下载数。Stars 来源为 [GitHub 官方 API](https://api.github.com/search/repositories?q=language%3AMoonBit+archived%3Afalse+fork%3Afalse&sort=stars&order=desc)，限定语言 MoonBit、非 fork、非 archived；不代表所有包含 MoonBit 文件的仓库。排名、版本、commit、抓取时间和 URL 均保存在 [manifest](manifest-2026-09-25.json)。

采用同一个已验收原生二进制；摘要保存其 SHA256、下载归档和源码清单摘要。默认与全规则扫描分别保留原始 JSON（gzip 压缩）；排除测试/示例等行为以每份报告的文件范围为准。各样本源码检查前后未变；不运行第三方应用。没有发现不能推出安全。

## 样本表

“完整”仅表示这次请求的语法范围完成。这里没有将全仓库扫描冒充编译器验证或全程序安全分析。

| 榜单/排名 | 项目 | 版本或 stars | 已解析/已选择 | 默认/全部线索 | 语法状态 |
|---|---|---|---:|---:|---|
| 下载 1 | moonbitlang/x | 0.5.5 | 81/81 | 0/0 | 完整 |
| 下载 2 | moonbitlang/async | 0.22.4 | 179/179 | 0/13 | 完整 |
| 下载 3 | mizchi/x | 0.6.1 | 84/84 | 0/104 | 完整 |
| 下载 4 | mizchi/zlib | 0.4.9 | 17/17 | 0/5 | 完整 |
| 下载 5 | moonbitlang/quickcheck | 0.14.0 | 30/34 | 0/1 | 不完整 |
| 下载 6 | moonbitlang/parser | 0.4.0 | 94/94 | 0/0 | 完整 |
| 下载 7 | mizchi/bitflow | 0.4.1 | 11/12 | 0/0 | 不完整 |
| 下载 8 | mizchi/tempfile | 0.1.2 | 2/2 | 0/0 | 完整 |
| 下载 9 | mizchi/llm | 0.3.2 | 38/38 | 0/5 | 完整 |
| 下载 10 | bobzhang/lexer | 0.2.2 | 1/1 | 0/0 | 完整 |
| 下载 11 | bobzhang/toml | 0.4.3 | 15/15 | 0/2 | 完整 |
| 下载 12 | moonbitlang/yacc | 0.7.22 | 66/66 | 0/4 | 完整 |
| Stars 1 | moonbitlang/moonbit-docs | 2440★ | 789/823 | 0/40 | 不完整 |
| Stars 2 | moonbitlang/core | 1218★ | 478/478 | 0/0 | 完整 |
| Stars 3 | mizchi/actrun | 668★ | 62/62 | 0/33 | 完整 |
| Stars 4 | nikivdev/mbt | 488★ | 71/91 | 0/0 | 不完整 |
| Stars 5 | moonbitlang/moonbit-course | 232★ | 32/41 | 0/4 | 不完整 |
| Stars 6 | paipai-Studio/BioSeqs | 196★ | 443/443 | 2/40 | 完整 |
| Stars 7 | mizchi/luna.mbt | 171★ | 356/357 | 0/126 | 不完整 |
| Stars 8 | trkbt10/indexion | 151★ | 505/506 | 0/9 | 不完整 |
| Stars 9 | moonbit-community/rabbita | 129★ | — | — | 未导入 |
| Stars 10 | mizchi/markdown.mbt | 102★ | 98/98 | 0/5 | 完整 |
| Stars 11 | oboard/mocket | 95★ | 37/37 | 0/3 | 完整 |
| Stars 12 | moonbitlang/openseek | 89★ | 1073/1094 | 0/53 | 不完整 |

## 编译器抽样与不完整原因

每个榜单按排名先取 3 个成功导入样本，选择最浅的一个 module，以固定 moon `0.1.20260920` / native 进行项目验证；未选中的 module 在摘要中列出。**不是每个仓库、每个后端均已编译验证。**

- 下载榜 `mizchi/x`：compiler_verified。
- `moonbitlang/x`：scope_incomplete，编译器选源与扫描器支持范围未完全吻合。
- `moonbitlang/async` 发布包：compiler_rejected，workspace 声明的 `test_programs` 不在归档内；不能据此称上游源码错误。
- `moonbit-docs`：仅最浅 module `legacy/examples/avl_tree` 的 2 个编译文件验证通过，不代表整个文档仓库。
- `core`、`actrun`：snapshot_unavailable；现有生产快照将 README/CLAUDE 的符号链接也拒绝，阻碍合法仓库验证。这是工具可用性限制。
- 额外对有默认发现的 **BioSeqs** 进行 native 编译检查，443/443 文件，compiler_verified；其声明偏好后端是 wasm-gc，本轮没有验证该后端运行行为。

未完整解析的 8 个样本涉及历史 `try?`、`loop`、已废弃 `for { ... }` 等语法，也包含文档错误示例、实验文件或 fixture；不能把所有解析失败都解释为官方新语法缺陷。应先判定文件用途和目标工具链再分类。

`rabbita` 归档含 `vite-plugin/test/project1/node_modules` 指向归档外的链接，导入器拒绝且不留下半成品目录。本轮未扫描它，也没有静默删掉链接后宣称完整检查。其他仓库内合法链接按原样保留。

## 两条默认线索的复核

均来自 BioSeqs 的 `src/seqxml_io.mbt`：`seqxml_escape_attr`、`seqxml_escape_text` 通过链式 `.replace` 编码 XML 特殊字符。

**独立 LLM 层**：使用用户指定的自定义 OpenAI 兼容服务，对两条发现及有限源码窗口进行复核。最终均为 `needs_review`，说明缺少真实调用绑定和替换次数语义。每条引用通过最终实现的整行精确匹配、源码 SHA 和发现 ID 校验；仍是 `llm_unverified`，静态输入的未验证状态原样保留。[复核结果](llm-biosequences-review-2026-09-25.json)、[上下文包](llm-biosequences-bundle-2026-09-25.json)。包中的绝对路径用于原环境校验；迁移环境后应从原报告重新 prepare。

联调共 3 次显式 API 请求：首轮默认格式/4096 输出预算失败，未接受；第二轮启用 JSON 模式及 8192 预算通过；输入报告保护/分页/严格引用修复后，第三轮以最终代码再次通过。首轮旧诊断只记录“非完整/非 JSON 响应”，不能事后断言具体是 token 截断。零自动重试。密钥、endpoint、私人模型名不进入公开验收文件。

**人工补证**：在固定工具链下复制两个纯函数到隔离 module，执行 `&&` 和 `<<`，分别得到 `&amp;&` 与 `&lt;<`，保留一个未转义字符。核对原文件调用点发现它们用于 XML 属性和文本输出；这是可复现的函数级不完整转义线索。没有验证完整应用的输入可信度、部署方式或实际利用，不能写作已证实应用漏洞。[复现源码、指纹、输入输出及边界](bioseqs-escaping-reproduction-2026-09-25.json)。建议上游在其实际工具链核实绑定后使用全量替换或专用 XML 编码器，并增加重复字符往返测试。本轮未向上游发送 issue/消息。

## 对 moon-audit 的后续优先级

1. **P0：按真实失败样本建立解析兼容清单。** 每项固定源码/工具链，区分历史语法、负例和未知语法。优先 QuickCheck、bitflow 的小文件；验收要求编译器选源可核对、位置和规则结果正确，未支持继续 exit 2。
2. **P0：缩小快照读取到实际安全边界。** 目前文档链接会阻断 core/actrun。先定义编译器输入、依赖、配置的快照范围，再增加“源码链接仍拒绝、无关文档链接不阻断、路径变化可检测”的反例，不能简单放开所有链接。
3. **P1：丰富复核证据而不是提高模型确信程度。** 本轮 LLM 准确指出缺少调用绑定；下一步可将已验证的函数身份、固定 core 行为、直接调用点作为独立、有 SHA 和行号的上下文附件。先保留模型无法判断的结论，不凭名称补全语义。
4. **P1：对显式全规则的 447 条线索分层抽样。** 当前没有逐条人工标注，不能报告精确率/召回率。维持两条默认规则，按项目/规则抽样形成标注集后再调整默认策略。

本轮没有扩展通用堆分析、调用图或 Tai-e 级别能力，重点是可复现语料、诚实覆盖状态与可运行复核流程。

## 复现

```bash
python3 scripts/popular_projects.py discover --output /tmp/popular-manifest.json
# 重现本轮请使用仓库内已固定的 manifest，重新 discover 会产生新排名/版本。
python3 scripts/popular_projects.py run \
  --manifest experiments/popular_projects/manifest-2026-09-25.json \
  --work-dir /tmp/popular-sources --analyzer /path/to/moon-audit \
  --output-dir /tmp/popular-results --toolchain /path/to/project-moon
```

依赖 Python 3.12+；发现 GitHub 排名使用 `gh`，固定 manifest 扫描使用标准 HTTPS 下载。归档读取上限 100 MiB，解包上限 50,000 项/512 MiB。`summary.json` 的 `harness_complete=false` 反映 rabbita 未导入；不把这个状态改成绿色来掩盖缺失。原始扫描报告以 `.json.gz` 保存，解压后可直接用于离线 LLM prepare。目录内包含由第三方公开源码派生的有限片段，归属其原项目，固定来源见 manifest。
