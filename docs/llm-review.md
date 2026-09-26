# 可选 LLM 复核：自定义 OpenAI 兼容 API

此功能读取静态报告、有限源码窗口及可用的编译器关联证据，输出带引用的**未验证意见**。不改变静态证据、baseline、扫描错误或未分析范围。它不自动寻找新漏洞，不证明项目安全，也不替代编译器绑定和数据流分析。

原生扫描不依赖 Python；此可选助手需要 **Python 3.12+**，仅使用标准库。源码仓库中脚本位于 `scripts/`，原生开发包中位于 `extras/`，将下面的路径对应替换即可。

## 使用

```bash
moon-audit --format json /path/to/project > /tmp/scan.json
# exit 1 表示有发现，exit 2 表示扫描不完整；都应保留 JSON 及状态。
python3 scripts/llm_review.py prepare \
  --report /tmp/scan.json --project /path/to/project --output /tmp/review-bundle
python3 scripts/llm_api_review.py \
  --bundle /tmp/review-bundle --env-file .env --output /tmp/review.json
```

`.env` 内容示例（实际密钥只留在本机，勿提交）：

```dotenv
OPENAI_BASE_URL=https://provider.example/v1
OPENAI_MODEL=your-model
OPENAI_API_KEY=your-secret
```

也支持已有配置名 `Base_URL`、`Model`、`API_KEY`。顺序：显式 CLI 选项 → 进程环境变量 → 指定 dotenv 文件；同一来源优先标准名。默认不自动读取 `.env`，需指定 `--env-file`。dotenv 仅解析赋值、引号和注释，不执行 shell、不替换 `$变量`。密钥通过环境变量或文件提供；`--api-key-env MY_KEY` 接受的是变量名。

`--base-url` 包含服务版本前缀；助手追加 `/chat/completions`，已包含该后缀时不重复追加。远程服务要求 HTTPS；loopback 本地服务允许 HTTP 和 `--anonymous`。不跟随重定向、不关闭 TLS 校验。不会写出密钥或 endpoint；本地复核结果记录配置模型名、数字 token 用量和响应摘要。

兼容性选项：

- `--json-mode`：服务支持时要求 `response_format={"type":"json_object"}`。无论是否开启，本地严格校验 JSON 和源码引用。
- `--token-parameter max_completion_tokens`：替代默认 `max_tokens`，适配不同服务。
- `--max-output-tokens 8192`：默认 4096，最大 16384。含推理 token 的服务可能需要更多预算。
- `--timeout 120`：单次网络操作超时，默认 90 秒、最大 180 秒；不是整个流程的硬总时限。
- `--retries 1`：只对 HTTP 429/5xx 有限重试，默认 0、最多 2。鉴权失败、格式/引用错误不重试。

只有显式执行 API 助手才上传上下文。请求最多 512 KiB，响应最多 2 MiB，模型 JSON 最多 1 MiB。超限/拒绝/截断/工具调用/伪造引用/源码变更均失败并保留旧结果，不把失败算作复核完成。服务响应必须是单条、`finish_reason=stop`、纯 JSON；不自动修补模型答案。

## 离线复核与批次

`prepare` 不调用模型，产生 `bundle.json` 和 `prompt.txt`。可人工检查后将 prompt 交给其他模型，再运行：

```bash
python3 scripts/llm_review.py validate \
  --bundle /tmp/review-bundle --response /tmp/model-response.json --output /tmp/review.json
# 超过 20 条时，后续批次使用不同输出目录；ID 在同一报告内保持稳定。
python3 scripts/llm_review.py prepare --report /tmp/scan.json \
  --project /path/to/project --offset 20 --max-findings 20 --output /tmp/review-batch-2
```

默认最多 20 条发现、80,000 字符上下文、每文件 2 MiB、前后各 12 行。预算只能调小，超出部分明确披露；分页不等于汇总完成，当前不自动合并批次。只读取项目内普通 `.mbt` 文件；拒绝符号链接、目录穿越和特殊文件。源码 SHA、位置、snippet 和已有快照参与核验；源码变化后需重新准备。

意见类别为 `needs_review`、`likely_false_positive`、`supported_concern`、`insufficient_context`，全部带 `llm_unverified`。强意见必须有匹配真实行范围的完整引用。`scope_complete` 仅指本包意见是否齐全、上下文是否可用；静态扫描的不完整状态另行保留。没有发现时不调用 API，也不能据此宣称安全。

提示词将源码/注释视为不可信数据，模型没有工具执行权。哈希用于检测意外修改，不是数字签名；本地包仍需来自可信生成流程。复核意见的文字可能错误，证据引用通过只代表文本与源码相符。

## 编译器关联证据

新的 `semantic` 报告带有 AST 函数/回调范围。`prepare` 会用告警的完整数据流路径匹配报告中的 route，从该入口沿 IR `Call` 选择辅助函数；不根据同名函数、文件名或附近位置猜调用目标。

每条具备这些证据的告警会附带：

- 对应 route、保存的数据流路径及其完整/部分状态；
- 可达函数的顺序 IR、生产编译单位与源码映射；
- 相关范围内的原始绑定查询、报告声明的库模型和成立前提；
- 完整的相关函数或回调行范围，含文件 SHA-256、真实行号和 `attachment_id`。

这里检查的是**可信扫描报告的内部一致性及输入是否仍相同**，不重新执行编译器绑定，也不证明报告真实来源。原始 binding 查询只作报告证据；IR 调用边决定辅助函数选择。项目外 core 源码不会按同名文件读取，模型清单也不是该复核层重新验证的运行语义。

请求前后重新检查整个项目输入快照的路径集合与 SHA，包括配置、依赖及新增/删除源码；沿用扫描器忽略 `.git/_build/.recovery` 的边界。上限为 100,000 个输入、单文件 16 MiB、合计 256 MiB、目录深度 64、每次检查 30 秒。不会把这些文件全部发送给模型，只发送选中的附件。

每个告警最多关联 64 个 IR 函数。80,000 字符上下文预算由原窗口与序列化证据共享；函数放不下时整份语义附件标记 `unavailable`，不裁切后冒充完整函数。最终提示词另限 256 KiB；实际 API 请求仍受 512 KiB 上限约束。默认最多 20 条、分页与其他限制不变。

引用跨文件附件时，响应证据除 `file/start_line/end_line/quote` 外还须包含本条告警的 `attachment_id`。逐行引用必须与所提供的附件完全相同，不能使用另一条告警的附件。源码支持 LF/CRLF 和正常 Unicode；AST 行号与文件行号无法统一处理的 U+2028/U+2029/裸 CR 暂时明确拒绝语义附件。

旧报告没有函数范围、路径/身份冲突、快照失效、未知 IR 或超预算时，仍保留原告警窗口，但披露语义证据缺失；这类告警只接受 `needs_review` 或 `insufficient_context`。`scope_complete` 也反映此缺口。普通 `syntax_hint` 尚未获得真实绑定时仍使用窗口，不会因这一改进自动升级。

这次交付完善**已有告警的复核证据**；尚未实现模型主动补查、无告警项目的漏洞发现或自动批次汇总。接口验收通过不等于误报率/漏报率已得到统计证明。

## 验收依据

本地 HTTP 服务测试覆盖请求协议、配置别名、重试、重定向、拒绝/截断、伪造引用和请求前后源码变化；CI 不读取密钥，不调用真实模型。真实 `.env` 联调使用公开 BioSeqs 两条发现，结果与失败过程见[热门项目审查](https://github.com/I3eg1nner/moon-audit/blob/codex/popular-projects-llm-20260925/experiments/popular_projects/README.md)。

协议参考：[官方 Chat Completions 文档](https://developers.openai.com/api/reference/cli/resources/chat)、[JSON 模式与结构化输出说明](https://developers.openai.com/api/docs/guides/structured-outputs)。自定义服务实现可能不同，以本地契约校验和实际联调结果为准。

编译器关联上下文的独立复核、提取包验收及两次真实 `.env` 对照请求见[证据增强实验](../experiments/llm_evidence/README.md)。窗口版缺少 helper 行为，增强版引用了三条路径对应的实际函数；这只是固定小样本的解释改善，不是项目级精度保证。
