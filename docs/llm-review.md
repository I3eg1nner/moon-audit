# 可选 LLM 复核：自定义 OpenAI 兼容 API

此功能读取静态报告和有限源码窗口，输出带引用的**未验证意见**。不改变静态证据、baseline、扫描错误或未分析范围。它不自动寻找新漏洞，不证明项目安全，也不替代编译器绑定和数据流分析。

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

## 验收依据

本地 HTTP 服务测试覆盖请求协议、配置别名、重试、重定向、拒绝/截断、伪造引用和请求前后源码变化；CI 不读取密钥，不调用真实模型。真实 `.env` 联调使用公开 BioSeqs 两条发现，结果与失败过程见[热门项目审查](https://github.com/I3eg1nner/moon-audit/blob/codex/popular-projects-llm-20260925/experiments/popular_projects/README.md)。

协议参考：[官方 Chat Completions 文档](https://developers.openai.com/api/reference/cli/resources/chat)、[JSON 模式与结构化输出说明](https://developers.openai.com/api/docs/guides/structured-outputs)。自定义服务实现可能不同，以本地契约校验和实际联调结果为准。
