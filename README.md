# moon-audit

MoonBit 静态安全分析工具。基于 AST 语法树分析，检测通用安全问题（unsafe 调用、未受控 panic、类型强转）和 Web 框架漏洞模式（XSS、CORS、CRLF 注入等）。

## 工作原理

```
                    ┌─────────────┐
                    │  .mbt 源码   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Import 分析  │ ← moon.pkg/moon.mod
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  AST 解析    │ ← moonbitlang/parser
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │  14 条 CWE 规则匹配      │ ← Import 门控过滤
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │  报告输出    │ → Text / JSON / SARIF
                    └─────────────┘
```

1. **Import 分析**：解析 `moon.pkg` 和 `moon.mod` 提取项目依赖，构建 `ImportContext`
2. **AST 解析**：使用 `moonbitlang/parser` 将 `.mbt` 源文件解析为语法树
3. **规则匹配**：每条规则实现 `IterVisitor` trait，遍历 AST 匹配漏洞模式
4. **Import 门控**：仅在项目实际引入相关框架（mocket、crescent、cmark、rabbita）时激活对应规则，从源头消除无关误报
5. **上下文感知过滤**：通用规则自动识别 FFI 绑定层（`extern "js"` / `#external`）、guard 校验模式、平台桩文件等安全上下文，抑制已知安全的模式
6. **报告输出**：支持 Text / JSON / SARIF 2.1.0（兼容 GitHub Code Scanning），每条 Finding 包含 confidence 级别和稳定 fingerprint

可选辅助子命令（不在核心分析管线中）：
- `llm-analyze`：将 Finding 连同源码上下文生成结构化提示词，调用大模型判定真阳/假阳
- `generate-poc`：按 CWE 类型生成验证脚本模板
- `remediate`：生成修复建议和代码示例

## 真实项目扫描效果

对 MoonBit 生态 15 个开源项目（总计 2,438 个文件）的全流程扫描结果：

| 项目 | Stars | 扫描文件 | 检出数 | 检出类型 |
|---|---|---|---|---|
| [moonbitlang/core](https://github.com/moonbitlang/core) | 1154 | 438 | 813 | unsafe 调用 (623)、panic/abort (190) |
| [mizchi/luna.mbt](https://github.com/mizchi/luna.mbt) | 162 | 466 | 15 | CRLF 注入 (CWE-113) |
| [moonbit-community/rabbita](https://github.com/moonbit-community/rabbita) | 119 | 155 | 46 | unsafe cast (25)、panic/abort (21) |
| [mizchi/markdown.mbt](https://github.com/mizchi/markdown.mbt) | 97 | 82 | 0 | - |
| [oboard/mocket](https://github.com/oboard/mocket) | 94 | 50 | 9 | CRLF 注入、CORS、Cookie、panic |
| [mizchi/js.mbt](https://github.com/mizchi/js.mbt) | 74 | 196 | 0 | - |
| [moonbitlang/async](https://github.com/moonbitlang/async) | 65 | 188 | 149 | unsafe 调用 (100)、panic/abort (47)、unsafe cast (2) |
| [mizchi/tornado](https://github.com/mizchi/tornado) | 62 | 26 | 0 | - |
| [mizchi/pkfire](https://github.com/mizchi/pkfire) | 48 | 18 | 0 | - |
| [moonbitlang/maria](https://github.com/moonbitlang/maria) | 43 | 266 | 0 | - |
| [moonbit-community/selene](https://github.com/moonbit-community/selene) | 41 | 368 | 0 | - |
| [justjavac/moonbit-webview](https://github.com/justjavac/moonbit-webview) | 39 | 31 | 0 | - |
| [extism/moonbit-pdk](https://github.com/extism/moonbit-pdk) | 38 | 19 | 0 | - |
| [moonbit-community/cmark.mbt](https://github.com/moonbit-community/cmark.mbt) | 34 | 51 | 47 | unsafe_to_char、panic/abort、cmark safe=false |
| [bobzhang/crescent](https://github.com/bobzhang/crescent) | 5 | 70 | 13 | unsafe 调用、panic、Cookie、CORS、DoS |

通用安全规则（CWE-676/248/704）覆盖所有 MoonBit 项目，内置上下文感知过滤（FFI 绑定层、guard 校验、平台桩文件等安全模式自动跳过）；Web 框架规则通过 Import 门控仅在相关依赖存在时激活。core/async 等基础库的 unsafe 调用属于预期使用，应用项目可通过 `.moon-audit.json` 按需配置。

### 已提交的安全修复 PR

| 项目 | 漏洞 | PR |
|---|---|---|
| cmark.mbt | 存储型 XSS (CWE-79) — render() 默认 safe=false（已由上游修复为 safe=true） | [moonbit-community/cmark.mbt#137](https://github.com/moonbit-community/cmark.mbt/pull/137) |
| crescent | CORS 凭证窃取 (CWE-942) + 会话劫持 (CWE-614) + 资源耗尽 DoS (CWE-770) | [bobzhang/crescent#44](https://github.com/bobzhang/crescent/pull/44) |
| mocket | 反射型 XSS (CWE-79) + 目录穿越 (CWE-22) | [oboard/mocket#12](https://github.com/oboard/mocket/pull/12) |
| async | CRLF 注入 (CWE-113) | [moonbitlang/async#494](https://github.com/moonbitlang/async/pull/494) |

## 功能特性

- **14 条安全检测规则**，覆盖通用安全（unsafe 调用、panic、类型强转）和 OWASP Top 10（注入、访问控制、安全配置错误）
- **Import 门控**：根据项目依赖自动激活相关规则，降低误报率
- **上下文感知过滤**：自动识别 FFI 绑定、guard 校验、平台桩文件等安全上下文，抑制已知安全模式的误报
- **Confidence 分级**：每条 Finding 标注 High/Medium/Low 置信度，区分确定性检测与启发式检测
- **稳定 Fingerprint**：基于 rule_id + 代码片段的 FNV-1a 哈希，不因行号变动产生重复告警
- **多格式输出**：支持 Text、JSON、SARIF 2.1.0（兼容 GitHub Code Scanning `partialFingerprints`）
- **CI 友好**：默认 exit 0（信息模式），`--fail-on-error` 显式启用 CI 阻断
- **污点追踪**：追踪用户输入从 Source 到 Sink 的数据流
- **扫描报告统计**：按规则、文件、CWE、OWASP 分类聚合分析结果
- **可选辅助子命令**：LLM 辅助分析、PoC 验证脚本生成、修复建议引擎

## 检测规则

### 通用安全规则（无 Import 门控）

| 规则 ID | 描述 | 上下文过滤 | 严重级别 |
|---|---|---|---|
| CWE-676/unsafe-call | `unsafe_*` 函数绕过运行时安全检查 | guard body 内已验证输入时跳过 | Warning |
| CWE-248/panic-reachable | 库代码中 `panic()`/`abort()` 使调用者无法恢复 | guard-else 模式、平台桩文件、abort("unreachable") 跳过 | Warning |
| CWE-704/unsafe-cast | `.cast()` 绕过类型系统，运行时可能产生无效值 | FFI 绑定文件（extern "js" / #external）跳过 | Warning |
| CWE-116/replace-escaping | `String::replace()` 仅替换首次出现，HTML 转义不完整 | - | Error |
| CWE-94/eval-extern | extern JS 中使用 `eval()`/`new Function()` | - | Error |
| CWE-22/path-concat | 路径拼接可能导致目录穿越 | - | Warning |

### Web 框架规则（Import 门控）

| 规则 ID | 描述 | 门控 |
|---|---|---|
| CWE-79/cmark-unsafe | cmark 渲染时显式 `safe=false`，允许原始 HTML 注入 | cmark |
| CWE-79/inner-html | `inner_html()` 接收动态内容，DOM XSS | rabbita |
| CWE-79/template-injection | HTML 响应中使用字符串插值，反射型 XSS | mocket/crescent |
| CWE-113/crlf-injection | HTTP 响应头注入动态值，CRLF 注入 | 通用 |
| CWE-942/cors-credentials | CORS `credentials=true` 且未限制 Origin | mocket/crescent |
| CWE-614/cookie-attrs | Cookie 缺少 HttpOnly/Secure/SameSite 属性 | mocket/crescent |
| CWE-770/no-body-limit | 服务器无请求体大小限制，DoS 风险 | mocket/crescent |
| CWE-346/ws-origin | WebSocket 无 Origin 校验 | mocket/crescent |

## 快速开始

### 安装

**方式一：构建独立二进制（推荐）**

```bash
git clone https://github.com/I3eg1nner/moon-audit.git
cd moon-audit
moon install && moon build --target native
# 二进制位于 _build/native/debug/build/src/main/main.exe
# 可选：复制到 PATH
cp _build/native/debug/build/src/main/main.exe /usr/local/bin/moon-audit
```

构建完成后即可独立使用，无需保留源码目录。

**方式二：作为库依赖**

```bash
moon add minie135/moon-audit
```

### 一键全流程分析（pipeline）

```bash
moon-audit pipeline /path/to/project
```

一条命令完成核心分析，输出到 `moon-audit-report/` 目录：

```
[1/3] Static scan...        → scan-results.txt / .json / .sarif
[2/3] Taint analysis...     → taint-analysis.txt
[3/3] Summary report...     → summary.txt / .json
```

完成后提示可选的下一步操作：

```
Next steps (optional):
    moon-audit llm-analyze /path/to/project   # LLM-assisted triage
    moon-audit generate-poc /path/to/project   # PoC exploit templates
    moon-audit remediate /path/to/project      # Fix guide
```

指定输出目录：

```bash
moon-audit pipeline -d ./my-report /path/to/project
```

### 分步执行

也可以单独运行每个阶段：

```bash
# 静态扫描
moon-audit /path/to/project

# LLM 验证
moon-audit llm-analyze --format script /path/to/project
python3 llm_analyze.py

# PoC 验证
moon-audit generate-poc -o poc.md /path/to/project

# 修复建议
moon-audit remediate -o fixes.md /path/to/project

# 统计报告
moon-audit summary /path/to/project
```

> 如果未安装到 PATH，将 `moon-audit` 替换为 `moon run src/main --`（在项目目录下运行）。

## 使用方式

### 扫描项目

```bash
moon-audit /path/to/moonbit-project
```

默认 exit 0（信息模式），不阻断 CI。使用 `--fail-on-error` 在发现 Error 级别漏洞时退出 1：

```bash
moon-audit --fail-on-error /path/to/project
```

### 指定输出格式

```bash
# JSON 格式
moon-audit --format json /path/to/project

# SARIF 格式（GitHub Code Scanning）
moon-audit --format sarif -o results.sarif /path/to/project
```

### 列出所有规则

```bash
moon-audit list-rules
```

### LLM 辅助分析

静态分析发现可能存在误报。`llm-analyze` 子命令读取项目 `.env` 配置，自动生成可执行的 LLM 验证脚本。

**第一步：配置 `.env` 文件**

```bash
cp .env.example .env
# 编辑 .env，填入你的 API 密钥
```

`.env` 配置项：

```bash
# Anthropic Claude API
LLM_API_KEY=sk-ant-api03-xxxxx
LLM_BASE_URL=https://api.anthropic.com/v1/messages
LLM_MODEL=claude-sonnet-4-20250514

# 或使用 OpenAI 兼容 API（如 DeepSeek、本地 Ollama 等）
# LLM_API_KEY=sk-xxxxx
# LLM_BASE_URL=https://api.deepseek.com/v1/chat/completions
# LLM_MODEL=deepseek-chat
```

**第二步：生成并运行分析脚本**

```bash
# 生成自动化分析脚本（读取 .env 配置）
moon-audit llm-analyze --format script /path/to/project

# 运行分析（自动调用 LLM API，逐条验证每个 Finding）
python3 llm_analyze.py
```

脚本会逐条发送 Finding 给 LLM，输出：
- 每条 Finding 的真阳性/假阳性判定
- 置信度评分 (0.0-1.0)
- 详细分析推理
- 修复建议
- 汇总统计 + JSON 结果文件 `llm_analysis_results.json`

**其他输出格式：**

```bash
# JSON 格式（Claude API 请求体，便于自定义集成）
moon-audit llm-analyze --format json /path/to/project

# Markdown 格式（人类可读的提示词文档）
moon-audit llm-analyze --format text /path/to/project
```

自动兼容 Anthropic Claude API 和 OpenAI 兼容 API（DeepSeek、Ollama 等），根据 `LLM_BASE_URL` 自动切换请求格式。

### 动态部署 PoC 漏洞验证

根据静态扫描发现，生成针对目标环境的 PoC 验证脚本。脚本部署到运行中的服务实例，验证漏洞在真实条件下的可达性：

```bash
# 生成 PoC 验证报告
moon-audit generate-poc /path/to/project

# 保存到文件
moon-audit generate-poc -o poc.md /path/to/project
```

生成的 PoC 脚本针对 CORS 错误配置、Cookie 属性缺失、请求体 DoS、XSS 注入、路径穿越、CRLF 注入等 CWE 类型，每个脚本包含：
- 攻击步骤说明
- 可执行的 Python 验证脚本（需指向目标服务地址）
- 预期结果与判定条件

### 修复建议

为每种检出的 CWE 漏洞类型生成修复指南，含 Before/After 代码示例和 OWASP 分类：

```bash
moon-audit remediate /path/to/project
moon-audit remediate -o fixes.md /path/to/project
```

### 扫描统计报告

按规则、文件、CWE、OWASP 分类聚合分析结果，输出风险评分：

```bash
# 文本格式统计面板
moon-audit summary /path/to/project

# JSON 格式（便于集成到 CI/CD）
moon-audit summary --format json -o summary.json /path/to/project
```

### 配置文件

在项目根目录创建 `.moon-audit.json`：

```json
{
  "rules": {
    "CWE-116/replace-escaping": { "enabled": true, "severity": "error" },
    "CWE-94/eval-extern": { "enabled": false }
  },
  "exclude": ["_build", ".mooncakes", "*_test.mbt"]
}
```

## 集成到 CI

### GitHub Actions（推荐）

在项目中添加一个 workflow 文件即可，moon-audit 自动安装 MoonBit 工具链、运行扫描、上传结果到 GitHub Security：

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: I3eg1nner/moon-audit@main
```

扫描结果自动出现在 **Security → Code scanning alerts** 页面。

#### 配置选项

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    path: '.'                  # 扫描路径（默认当前目录）
    format: 'sarif'            # 输出格式：text, json, sarif（默认 sarif）
    severity: 'warning'        # 最低报告级别：error, warning, info
    fail-on-findings: 'false'  # 发现漏洞时是否阻断 CI（默认 false）
    upload-sarif: 'true'       # 上传 SARIF 到 GitHub Security（默认 true）
```

#### 常见用法

**发现漏洞时阻断 PR 合并：**

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    fail-on-findings: 'true'
```

**仅报告 Error 级别漏洞：**

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    severity: 'error'
    fail-on-findings: 'true'
```

**输出 JSON 报告（不上传 SARIF）：**

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    format: 'json'
    upload-sarif: 'false'
```

**读取检出数量：**

```yaml
- uses: I3eg1nner/moon-audit@main
  id: audit
- run: echo "Found ${{ steps.audit.outputs.findings-count }} issue(s)"
```

### 其他 CI 系统（GitLab CI / Jenkins 等）

```bash
# 安装 MoonBit
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash
export PATH="$HOME/.moon/bin:$PATH"

# 克隆并运行 moon-audit
git clone --depth 1 https://github.com/I3eg1nner/moon-audit.git /tmp/moon-audit
cd /tmp/moon-audit && moon install
moon run src/main -- --format json -o "$PROJECT_DIR/audit.json" "$PROJECT_DIR"
```

## 作为库依赖调用

将 moon-audit 的扫描引擎嵌入到你的 MoonBit 项目中，用于构建自定义安全工具或编辑器插件。

**1. 添加依赖**

```bash
moon add minie135/moon-audit
```

**2. 在 `moon.pkg` 中引入**

```json
{
  "import": [
    { "path": "minie135/moon-audit/src", "alias": "audit" }
  ]
}
```

**3. 调用扫描 API**

```moonbit
fn check_security(project_path : String) -> Unit {
  let config = @audit.Config::default()
  let result = @audit.scan_project(project_path, config)

  let errors = result.findings.filter(fn(f) {
    f.severity == @audit.Error
  })

  if errors.length() > 0 {
    println(@audit.format_text(result, false))

    let remediations = @audit.get_all_remediations(errors)
    println(@audit.format_remediation_report(remediations))
  }
}
```

**4. 自定义规则配置**

```moonbit
fn custom_scan() -> Unit {
  let mut config = @audit.Config::default()
  config.rules["CWE-94/eval-extern"] = { enabled: true, severity: None }
  config = { ..config, min_severity: @audit.Info }

  let result = @audit.scan_project(".", config)

  let rules = @audit.list_all_rules()
  let summary = @audit.build_summary(result, rules)
  println(@audit.format_summary_text(summary))
  println("Risk: " + @audit.risk_level(@audit.risk_score(summary)))
}
```

**5. LLM 辅助验证集成**

```moonbit
fn llm_verify(project_path : String) -> Unit {
  let config = @audit.Config::default()
  let result = @audit.scan_project(project_path, config)
  let llm_config = @audit.load_llm_config(project_path)

  let sources : Map[String, String] = {}
  for f in result.findings {
    if !sources.contains(f.file) {
      let content = @fs.read_file_to_string(f.file) catch { _ => "" }
      sources[f.file] = content
    }
  }

  let imports = @audit.ImportContext::empty()
  let prompts = @audit.generate_batch_prompts(result.findings, sources, imports)
  let script = @audit.generate_llm_script(llm_config, prompts)
  @fs.write_string_to_file("verify.py", script)
  println("Run: python3 verify.py")
}
```

### 低误报配置推荐

moon-audit 通过 Import 门控大幅降低误报率。以下是针对不同项目类型的推荐配置：

**Web 服务项目**（使用 mocket/crescent）：

```json
{
  "rules": {
    "CWE-116/replace-escaping": { "enabled": true, "severity": "error" },
    "CWE-79/cmark-unsafe": { "enabled": true, "severity": "error" },
    "CWE-942/cors-credentials": { "enabled": true, "severity": "error" },
    "CWE-614/cookie-attrs": { "enabled": true, "severity": "warning" },
    "CWE-770/no-body-limit": { "enabled": true, "severity": "warning" },
    "CWE-113/crlf-injection": { "enabled": true, "severity": "error" },
    "CWE-94/eval-extern": { "enabled": false },
    "CWE-79/inner-html": { "enabled": false },
    "CWE-22/path-concat": { "enabled": false }
  }
}
```

**前端 Wasm 项目**（使用 rabbita）：

```json
{
  "rules": {
    "CWE-79/inner-html": { "enabled": true, "severity": "error" },
    "CWE-116/replace-escaping": { "enabled": true, "severity": "error" },
    "CWE-94/eval-extern": { "enabled": true, "severity": "error" },
    "CWE-942/cors-credentials": { "enabled": false },
    "CWE-614/cookie-attrs": { "enabled": false },
    "CWE-770/no-body-limit": { "enabled": false },
    "CWE-346/ws-origin": { "enabled": false }
  }
}
```

**通用库项目**（最低误报）：

```json
{
  "rules": {
    "CWE-116/replace-escaping": { "enabled": true, "severity": "error" },
    "CWE-94/eval-extern": { "enabled": false },
    "CWE-79/inner-html": { "enabled": false },
    "CWE-22/path-concat": { "enabled": false }
  }
}
```

> Import 门控原理：当项目未引入 `cmark`、`mocket`、`crescent`、`rabbita` 等包时，相关规则自动跳过，不会产生误报。手动禁用的规则适用于已知高误报场景（如 `eval-extern` 在非浏览器环境下无风险）。

## 项目结构

```
src/
├── scanner.mbt          # 主扫描引擎：目录遍历、AST 解析、规则调度
├── types.mbt            # 核心类型：Finding, Severity, RuleId, Config
├── helpers.mbt          # AST 参数检查工具函数
├── import_analysis.mbt  # moon.pkg/moon.mod 依赖分析
├── config.mbt           # .moon-audit.json 配置加载
├── env_config.mbt       # .env 文件解析 + LLM 脚本生成
├── output.mbt           # Text/JSON 输出格式化
├── sarif.mbt            # SARIF 2.1.0 输出
├── llm_prompt.mbt       # LLM 辅助分析提示词生成
├── poc_gen.mbt          # PoC 动态验证脚本生成
├── remediation.mbt      # 修复建议引擎
├── taint.mbt            # 污点追踪数据流分析
├── summary.mbt          # 扫描统计报告
├── cwe*.mbt             # 各 CWE 规则实现
├── scanner_test.mbt     # 核心规则测试
├── extended_test.mbt    # 扩展模块测试
└── main/main.mbt        # CLI 入口
```

## 开发

```bash
# 编译检查
moon check

# 运行测试
moon test

# 格式化代码
moon fmt
```

## 许可证

[MulanPSL-2.0](LICENSE)
