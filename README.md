# moon-audit

MoonBit 语法级安全扫描器，用 MoonBit 写成，检测 MoonBit 项目和第三方源码中的安全问题。

## 为什么需要 moon-audit？

MoonBit 是一门年轻的语言，社区正在快速长出 Web 框架（mocket、crescent）、Markdown 渲染器（cmark）、前端框架（rabbita）——但安全工具还是空白。

Semgrep、CodeQL 不认识 `.mbt` 文件。手动审计当然可以，但你不可能盯着每一个 PR 看 `set_cookie()` 有没有加 `http_only=true`、`handle_cors()` 有没有限制 Origin。

moon-audit 用 MoonBit 官方 parser 直接解析 AST，在语法树上匹配 14 条 CWE 安全规则。它知道 mocket 的 `handle_cors()` 应该限制 Origin，知道 cmark 的 `render(safe=false)` 会吞掉 XSS 防护，也知道 `extern "js"` 里的 `.cast()` 不是 bug 而是 FFI 的日常。

不需要运行时环境，不需要外部依赖，`moon build --target native` 编译出来就是一个独立二进制，扫一个项目几秒钟。

## 真实效果

对 MoonBit 生态 21 个开源项目（3,676 个文件）扫描，6 个项目检出漏洞，均已提交修复 PR，其中 4 个已被上游合并：

| 项目 | 检出 | 类型 | 修复 PR | 状态 |
|---|---|---|---|---|
| [mizchi/luna.mbt](https://github.com/mizchi/luna.mbt) | 14 | CRLF 注入 | [#103](https://github.com/mizchi/luna.mbt/pull/103) | ✅ 已合并 |
| [oboard/mocket](https://github.com/oboard/mocket) | 8 | XSS、CRLF 注入、Cookie、CORS、目录穿越 | [#12](https://github.com/oboard/mocket/pull/12) | ✅ 已合并 |
| [moonbit-community/crescent](https://github.com/moonbit-community/crescent) | 8 | Cookie、DoS、CORS | [#44](https://github.com/moonbit-community/crescent/pull/44) | 🔵 Open |
| [moonbitlang/async](https://github.com/moonbitlang/async) | 3 | CRLF 注入 | [#494](https://github.com/moonbitlang/async/pull/494) | ✅ 已合并 |
| [moonbit-community/rabbita](https://github.com/moonbit-community/rabbita) | 2 | 目录穿越 | [#126](https://github.com/moonbit-community/rabbita/pull/126) | ✅ 已合并 |
| [moonbit-community/cmark.mbt](https://github.com/moonbit-community/cmark.mbt) | 1 | XSS（已由上游修复为 safe=true） | [#137](https://github.com/moonbit-community/cmark.mbt/pull/137) | 🔵 Open |

其余 15 个项目未检出问题（未引入 Web 框架依赖，Import 门控自动跳过 Web 规则）。

moon-audit 通过多层手段控制误报：

1. **Import 门控**：Web 框架规则仅在项目引入相关框架时激活，从源头消除无关误报
2. **上下文过滤**：CWE-22 过滤 API 路由/HTML 标签/URL 拼接等非路径上下文（误报率 ~60% → ~19%）；CWE-113 追踪 let 绑定常量和全常量 match
3. **可选 LLM 复核**：将静态发现 + 源码上下文发送给 LLM 逐条研判

当前版本为 **0.5.0-dev**，所有发现均为 `syntax_hint`，不证明 API 身份或漏洞。零发现不等于项目安全。

## 安装

```bash
moon add minie135/moon-audit
```

或从源码构建：

```bash
moon update
moon build --target native --release
# 产物：_build/native/release/build/src/main/main.exe
```

Linux x86_64、macOS arm64、Windows x86_64 的原生开发包可从 [CI Artifacts](https://github.com/I3eg1nner/moon-audit/actions/workflows/native-delivery.yml) 下载。

## 快速开始

```bash
# 静态扫描
moon-audit --format json /path/to/project

# 指定规则
moon-audit --rule CWE-113/crlf-injection /path/to/project

# 增量扫描（只扫描变更文件，适合 CI）
git diff --name-only HEAD~1 > changed.txt
moon-audit --changed-files changed.txt /path/to/project

# 生成 baseline（存量项目首次接入时，过滤已知告警）
moon-audit generate-baseline -o baseline.json /path/to/project
moon-audit --baseline baseline.json /path/to/project

# 查看所有规则
moon-audit list-rules
```

### 快速示例

`examples/vulnerable_server.mbt` 包含一个带有路径遍历和 CRLF 注入问题的最小 Web 处理器：

```bash
moon run src/main -- --rule CWE-22/path-concat --rule CWE-113/crlf-injection examples/
```

预期输出 2 条发现（1× CWE-22 路径拼接，1× CWE-113 动态头部值），安全函数不触发告警。

### 输出格式

```bash
moon-audit --format json /path/to/project          # JSON
moon-audit --format sarif -o results.sarif /path/to  # SARIF（GitHub Code Scanning）
moon-audit --fail-on-error /path/to/project         # 有 Error 级别时 exit 1
```

退出码：`0` 完成无告警策略触发；`1` `--fail-on-error` 命中 Error 级发现；`2` 参数/解析/写入失败。

## 检测规则

14 条规则，覆盖通用安全和 Web 框架场景。

### 通用规则

| 规则 ID | 描述 | 默认 | 上下文过滤 |
|---|---|---|---|
| CWE-116/replace-escaping | `String::replace()` 仅替换首次出现，HTML 转义不完整 | 开启 | — |
| CWE-22/path-concat | 路径拼接可能导致目录穿越 | 关闭 | API 路由/HTML/URL/git ref/shell/框架内部路径/字符串比较方法参数跳过 |
| CWE-94/eval-extern | extern JS 中使用 `eval()`/`new Function()` | 关闭 | — |
| CWE-113/crlf-injection | HTTP 响应头注入动态值 | 关闭 | let 绑定常量/sanitized 变量/全常量 match 跳过 |
| CWE-248/panic-reachable | 库代码中 `panic()`/`abort()` 使调用者无法恢复 | 关闭 | — |
| CWE-676/unsafe-call | 危险类型转换 (`unsafe_from_*`/`unsafe_new`) | 关闭 | `unsafe_to_char`/`unsafe_to_byte` 跳过 |
| CWE-704/unsafe-cast | `.cast()`/`.reinterpret_cast()` 绕过类型系统 | 关闭 | — |

### Web 框架规则（Import 门控）

仅在项目引入相关框架时激活，从源头消除无关误报。

| 规则 ID | 描述 | 门控框架 |
|---|---|---|
| CWE-79/cmark-unsafe | cmark 渲染 `safe=false`，原始 HTML 注入 | cmark |
| CWE-79/inner-html | `inner_html()` 接收动态内容，DOM XSS | rabbita |
| CWE-79/template-injection | HTML 响应字符串插值，反射型 XSS | mocket/crescent |
| CWE-942/cors-credentials | CORS `credentials=true` 且未限制 Origin | mocket/crescent |
| CWE-614/cookie-attrs | Cookie 缺少 HttpOnly/Secure/SameSite | mocket/crescent |
| CWE-770/no-body-limit | 无请求体大小限制，DoS 风险 | crescent |
| CWE-346/ws-origin | WebSocket 无 Origin 校验 | mocket/crescent |

默认仅启用 `CWE-116/replace-escaping` 和 `CWE-79/cmark-unsafe`，其余通过 `--rule` 或配置文件启用。

## 配置

项目根目录创建 `.moon-audit.json`：

```json
{
  "rules": {
    "CWE-676/unsafe-call": { "enabled": true },
    "CWE-94/eval-extern": { "enabled": false }
  },
  "exclude": ["_build", ".mooncakes", "*_test.mbt"]
}
```

也可通过命令行按需启用：

```bash
moon-audit --rule CWE-676/unsafe-call --rule CWE-248/panic-reachable /path/to/project
```

## CI 集成

### GitHub Actions

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

默认不会导致 CI 失败——扫描结果仅上报到 GitHub Security 面板。显式设置 `fail-on-findings: 'true'` 时才阻断构建。

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    fail-on-findings: 'true'
    severity: 'error'
    upload-sarif: 'true'
```

## 可选 LLM 复核

独立 Python 助手，支持自定义 OpenAI 兼容 API：从 JSON 报告准备有限源码上下文，逐条核验发现。支持 `Base_URL` / `Model` / `API_KEY` 环境变量；`.env` 必须显式指定。所有模型意见均为 `llm_unverified`，不改变静态证据或 baseline。原生包附带 `extras/` 助手；仅此功能需要 Python 3.12+。[使用与边界](docs/llm-review.md)

## 可选项目验证与语义检测

默认语法扫描无需目标项目工具链。进阶功能：

```bash
# 项目验证：用项目自己的工具链编译检查、核对源码和依赖快照
moon-audit --verify-project --project-toolchain /path/to/project-moon \
  --target native --format sarif -o results.sarif /path/to/project

# 语义检测：固定 mocket get 回调的数据流追踪
moon-audit --analysis semantic --verify-project \
  --semantic-scope mocket-get-callbacks \
  --project-toolchain /path/to/project-moon --target native \
  --format json /path/to/project

# 多模块 workspace 扫描
moon-audit workspace /path/to/workspace
```

语义模式当前范围为 mocket `.get()` 回调的查询参数 → String helper → HTML responder 路径，复用同一 IR 接入 cmark 渲染模型。仅 native 后端、声明的 scope 内有效；不证明注册可达性、中间件行为或浏览器可利用性。详见各实验记录：[跨包验收](experiments/cross_package/README.md) · [编译上下文](experiments/compilation_context/README.md) · [workspace](experiments/workspace/README.md)

## 作为库依赖

```bash
moon add minie135/moon-audit
```

```moonbit
fn check_security(project_path : String) -> Unit {
  let config = @audit.Config::default()
  let result = @audit.scan_project(project_path, config)
  let errors = result.findings.filter(fn(f) { f.severity == @audit.Error })
  if errors.length() > 0 {
    println(@audit.format_text(result, false))
  }
}
```

## 工作原理

```
  .mbt 源码 → Import 分析 → AST 解析 → 14 条规则匹配 → 上下文过滤 → 报告输出
                                                                    ↓（可选）
                                                         LLM 复核 / 语义数据流
```

1. **Import 分析**：解析 `moon.pkg`/`moon.mod` 依赖，决定激活哪些 Web 规则
2. **AST 遍历**：每条规则实现 `IterVisitor` trait，遍历语法树匹配漏洞模式
3. **上下文过滤**：识别非路径上下文、常量变量、安全 match 等，抑制误报
4. **输出**：Text / JSON / SARIF 2.1.0，每条 Finding 含 confidence 分级和稳定 fingerprint

前端使用固定官方 parser `0.4.0+moon-audit-legacy.2`，已支持旧 `try?`、`loop` 语法和六个保留字标识符兼容。[前端对照](experiments/frontend_compat/README.md)

## 开发

```bash
moon test --target all --deny-warn
moon fmt --check
moon info
moon build --target native
python3 scripts/cli_regression_test.py
python3 scripts/detection_benchmark.py   # 检测回归基准（23 用例 × 6 规则）
```

构建固定 moonc `v0.10.14+7d59c7ec9`，依赖见 [moon.mod](moon.mod)。构建版本独立于待检测项目版本。

## 许可证

[MulanPSL-2.0](LICENSE)
