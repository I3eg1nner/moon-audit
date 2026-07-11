# moon-audit

MoonBit 生态安全静态分析工具。基于 AST 语法树分析，检测 MoonBit Web 应用中的安全漏洞。

## 功能特性

- **11 条安全检测规则**，覆盖 OWASP Top 10 中的注入、访问控制、安全配置错误等类别
- **Import 门控**：根据项目依赖自动激活相关规则，降低误报率
- **多格式输出**：支持 Text、JSON、SARIF 2.1.0（兼容 GitHub Code Scanning）
- **LLM 辅助分析**：生成结构化提示词，供 LLM 进行深度漏洞验证和误报过滤
- **PoC 自动生成**：根据检测结果生成 Python 漏洞利用脚本模板
- **修复建议引擎**：提供每种 CWE 的修复方案，含 Before/After 代码示例
- **污点追踪**：追踪用户输入从 Source 到 Sink 的数据流
- **扫描报告统计**：按规则、文件、CWE、OWASP 分类聚合分析结果

## 检测规则

| 规则 ID | 描述 | 严重级别 |
|---|---|---|
| CWE-116/replace-escaping | `String::replace()` 仅替换首次出现，HTML 转义不完整 | Error |
| CWE-79/cmark-unsafe | cmark 渲染 Markdown 时默认 `safe=false`，允许注入 | Error |
| CWE-79/inner-html | `inner_html()` 接收动态内容，DOM XSS | Error |
| CWE-79/template-injection | HTML 响应中使用字符串插值，反射型 XSS | Error |
| CWE-94/eval-extern | extern JS 中使用 `eval()`/`new Function()` | Error |
| CWE-113/crlf-injection | HTTP 响应头注入动态值，CRLF 注入 | Error |
| CWE-942/cors-credentials | CORS `credentials=true` 且未限制 Origin | Error |
| CWE-614/cookie-attrs | Cookie 缺少 HttpOnly/Secure/SameSite 属性 | Warning |
| CWE-770/no-body-limit | 服务器无请求体大小限制，DoS 风险 | Warning |
| CWE-346/ws-origin | WebSocket 无 Origin 校验 | Warning |
| CWE-22/path-concat | 路径拼接可能导致目录穿越 | Warning |

## 安装

```bash
moon add minie135/moon-audit
```

## 使用方式

### 扫描项目

```bash
moon run src/main -- /path/to/moonbit-project
```

### 指定输出格式

```bash
# JSON 格式
moon run src/main -- --format json /path/to/project

# SARIF 格式（GitHub Code Scanning）
moon run src/main -- --format sarif -o results.sarif /path/to/project
```

### 列出所有规则

```bash
moon run src/main -- list-rules
```

### LLM 辅助分析

静态分析发现可能存在误报。`llm-analyze` 子命令读取项目 `.env` 配置，自动生成可执行的 LLM 验证脚本。

**第一步：配置 `.env` 文件**

在待扫描项目根目录创建 `.env`：

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
moon run src/main -- llm-analyze --format script /path/to/project

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
moon run src/main -- llm-analyze --format json /path/to/project

# Markdown 格式（人类可读的提示词文档）
moon run src/main -- llm-analyze --format text /path/to/project
```

自动兼容 Anthropic Claude API 和 OpenAI 兼容 API（DeepSeek、Ollama 等），根据 `LLM_BASE_URL` 自动切换请求格式。

### PoC 漏洞利用脚本生成

根据扫描发现自动生成 Python 利用脚本模板，用于红队验证：

```bash
# 生成 PoC 报告
moon run src/main -- generate-poc /path/to/project

# 保存到文件
moon run src/main -- generate-poc -o poc-report.md /path/to/project
```

生成的 PoC 脚本覆盖 CORS 凭据窃取、Cookie 劫持、DoS 攻击、XSS 注入、路径穿越、CRLF 注入等攻击类型。

### 修复建议

为每种检出的 CWE 漏洞类型生成修复指南，含 Before/After 代码示例和 OWASP 分类：

```bash
moon run src/main -- remediate /path/to/project
moon run src/main -- remediate -o fixes.md /path/to/project
```

### 扫描统计报告

按规则、文件、CWE、OWASP 分类聚合分析结果，输出风险评分：

```bash
# 文本格式统计面板
moon run src/main -- summary /path/to/project

# JSON 格式（便于集成到 CI/CD）
moon run src/main -- summary --format json -o summary.json /path/to/project
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

## 架构

```
src/
├── scanner.mbt          # 主扫描引擎：目录遍历、AST 解析、规则调度
├── types.mbt            # 核心类型：Finding, Severity, RuleId, Config
├── helpers.mbt          # AST 参数检查工具函数
├── import_analysis.mbt  # moon.pkg/moon.mod 依赖分析
├── config.mbt           # .moon-audit.json 配置加载
├── output.mbt           # Text/JSON 输出格式化
├── sarif.mbt            # SARIF 2.1.0 输出
├── llm_prompt.mbt       # LLM 辅助分析提示词生成
├── poc_gen.mbt          # PoC 漏洞利用脚本生成
├── remediation.mbt      # 修复建议引擎
├── taint.mbt            # 污点追踪数据流分析
├── summary.mbt          # 扫描统计报告
├── cwe*.mbt             # 各 CWE 规则实现
├── scanner_test.mbt     # 核心规则测试
├── extended_test.mbt    # 扩展模块测试
└── main/main.mbt        # CLI 入口
```

### 工作原理

1. **Import 分析**：解析 `moon.pkg` 提取依赖信息，构建 `ImportContext`
2. **AST 解析**：使用 `moonbitlang/parser` 将 `.mbt` 源文件解析为语法树
3. **规则匹配**：每条规则实现 `IterVisitor` trait，遍历 AST 匹配漏洞模式
4. **门控过滤**：仅在项目使用相关框架时激活对应规则
5. **结果输出**：支持 Text/JSON/SARIF 多种格式

### LLM 辅助分析流程

```
静态分析发现 → 生成结构化提示词 → LLM 深度分析 → 误报过滤 → 高精度结果
```

`generate_analysis_prompt()` 将每个 Finding 转换为包含源码上下文、Import 信息和 MoonBit 语义提示的分析请求，输出 Claude API 兼容的 JSON 格式。

### PoC 验证流程

```
静态分析发现 → 分类 CWE 类型 → 生成 Python 利用脚本 → 红队验证
```

`generate_poc()` 为 CORS、Cookie、DoS、XSS、路径穿越、CRLF 注入等类型自动生成可执行的 PoC 脚本。

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
