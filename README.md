# moon-audit

MoonBit Native Audit — MoonBit 原生静态安全扫描器。

## 为什么需要 moon-audit？

MoonBit 是一门年轻的语言，社区正在快速长出 Web 框架（mocket、crescent）、Markdown 渲染器（cmark）、前端框架（rabbita）——但安全工具还是空白。

Semgrep、CodeQL 不认识 `.mbt` 文件。手动审计当然可以，但你不可能盯着每一个 PR 看 `set_cookie()` 有没有加 `http_only=true`、`handle_cors()` 有没有限制 Origin。

moon-audit 用 MoonBit 官方 parser 直接解析 AST，在语法树上匹配 14 条 CWE 安全规则。它知道 mocket 的 `handle_cors()` 应该限制 Origin，知道 cmark 的 `render(safe=false)` 会吞掉 XSS 防护，也知道 `extern "js"` 文件里的 `.cast()` 不是 bug 而是 FFI 的日常——会自动跳过。

不需要运行时环境，不需要外部依赖，`moon build --target native` 编译出来就是一个独立二进制，扫一个项目几秒钟。

## 真实效果

对 MoonBit 生态 21 个开源项目（3,676 个文件）扫描，4 个项目检出漏洞，其余 17 个零检出：

| 项目 | 检出 | 类型 | 修复 PR |
|---|---|---|---|
| [mizchi/luna.mbt](https://github.com/mizchi/luna.mbt) | 14 | CRLF 注入 | [#103](https://github.com/mizchi/luna.mbt/pull/103) |
| [oboard/mocket](https://github.com/oboard/mocket) | 8 | XSS、CRLF 注入、Cookie、CORS、目录穿越 | [#12](https://github.com/oboard/mocket/pull/12) |
| [bobzhang/crescent](https://github.com/bobzhang/crescent) | 8 | Cookie、DoS、CORS | [#44](https://github.com/bobzhang/crescent/pull/44) |
| [moonbit-community/cmark.mbt](https://github.com/moonbit-community/cmark.mbt) | 1 | XSS（已由上游修复为 safe=true） | [#137](https://github.com/moonbit-community/cmark.mbt/pull/137) |

另提交 async CRLF 注入修复 [moonbitlang/async#494](https://github.com/moonbitlang/async/pull/494)。

静态扫描的价值在于发现——它能在代码合入前低成本地扫出可疑模式，但不可避免地会有误报（luna.mbt 的 14 个 CRLF 检出中 11 个是 config 驱动的固定 header 值）。所以 moon-audit 在静态扫描之上还提供了 PoC 动态验证脚本生成和 LLM 辅助分析，用于在本地部署的靶机上实际复现，区分真正的漏洞和噪音。目前所有提交 PR 的漏洞均经过本地运行时验证确认。

## 快速开始

```bash
git clone https://github.com/I3eg1nner/moon-audit.git
cd moon-audit
moon install && moon build --target native

# 扫描项目（一键全流程）
./moon-audit pipeline /path/to/project

# 或单独运行静态扫描
./moon-audit /path/to/project
```

> 二进制位于 `_build/native/debug/build/src/main/main.exe`，可复制到 PATH。
> 也可通过 `moon add minie135/moon-audit` 作为库依赖使用。

### 输出格式

```bash
moon-audit --format json /path/to/project          # JSON
moon-audit --format sarif -o results.sarif /path/to  # SARIF（GitHub Code Scanning）
moon-audit --fail-on-error /path/to/project         # 有 Error 级别漏洞时 exit 1
```

## 检测规则

14 条规则，覆盖通用安全和 OWASP Top 10。

### 通用安全规则

| 规则 ID | 描述 | 默认 | 上下文过滤 |
|---|---|---|---|
| CWE-676/unsafe-call | 危险类型转换 (`unsafe_to_*`/`unsafe_from_*`/`unsafe_new`) | 关闭 | 性能操作、guard body 跳过 |
| CWE-248/panic-reachable | 库代码中 `abort("message")` 使调用者无法恢复 | 关闭 | 裸 panic、guard-else、平台桩、契约断言跳过 |
| CWE-704/unsafe-cast | `.cast()` 绕过类型系统 | 关闭 | FFI 绑定文件跳过 |
| CWE-116/replace-escaping | `String::replace()` 仅替换首次出现，HTML 转义不完整 | 开启 | — |
| CWE-94/eval-extern | extern JS 中使用 `eval()`/`new Function()` | 开启 | — |
| CWE-22/path-concat | 路径拼接可能导致目录穿越 | 开启 | — |

### Web 框架规则（Import 门控）

仅在项目引入相关框架时激活，从源头消除无关误报。

| 规则 ID | 描述 | 门控框架 |
|---|---|---|
| CWE-79/cmark-unsafe | cmark 渲染 `safe=false`，原始 HTML 注入 | cmark |
| CWE-79/inner-html | `inner_html()` 接收动态内容，DOM XSS | rabbita |
| CWE-79/template-injection | HTML 响应字符串插值，反射型 XSS | mocket/crescent |
| CWE-113/crlf-injection | HTTP 响应头注入动态值 | 通用 |
| CWE-942/cors-credentials | CORS `credentials=true` 且未限制 Origin | mocket/crescent |
| CWE-614/cookie-attrs | Cookie 缺少 HttpOnly/Secure/SameSite | mocket/crescent |
| CWE-770/no-body-limit | 无请求体大小限制，DoS 风险 | crescent |
| CWE-346/ws-origin | WebSocket 无 Origin 校验 | mocket/crescent |

标准库模块（`moonbitlang/core`、`moonbitlang/x` 等）自动跳过通用规则。

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

扫描结果自动出现在 **Security → Code scanning alerts**。

可选配置：

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    fail-on-findings: 'true'    # 发现漏洞时阻断 CI
    severity: 'error'           # 最低报告级别
    upload-sarif: 'true'        # 上传到 GitHub Security
```

### 其他 CI

```bash
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash
export PATH="$HOME/.moon/bin:$PATH"
git clone --depth 1 https://github.com/I3eg1nner/moon-audit.git /tmp/moon-audit
cd /tmp/moon-audit && moon install
moon run src/main -- --format json -o "$PROJECT_DIR/audit.json" "$PROJECT_DIR"
```

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

也可通过命令行按需启用规则：

```bash
moon-audit --rule CWE-676/unsafe-call --rule CWE-248/panic-reachable /path/to/project
moon-audit list-rules   # 查看所有规则
```

## 辅助功能

核心 pipeline 之外的可选子命令：

```bash
# LLM 辅助验证（需配置 .env 中的 API Key）
moon-audit llm-analyze --format script /path/to/project
python3 llm_analyze.py

# PoC 验证脚本生成
moon-audit generate-poc -o poc.md /path/to/project

# 修复建议（含 Before/After 代码示例）
moon-audit remediate -o fixes.md /path/to/project

# 统计报告（按 CWE/OWASP 分类聚合）
moon-audit summary /path/to/project
```

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
  .mbt 源码 → Import 分析(moon.pkg/moon.mod) → AST 解析(moonbitlang/parser) → 14 条规则匹配 → 报告输出(Text/JSON/SARIF)
```

1. **Import 分析**：解析依赖，构建 `ImportContext`，决定激活哪些 Web 规则
2. **AST 遍历**：每条规则实现 `IterVisitor` trait，遍历语法树匹配漏洞模式
3. **上下文过滤**：识别 FFI 绑定、guard 校验、平台桩文件等安全上下文，抑制误报
4. **输出**：Text / JSON / SARIF 2.1.0，每条 Finding 含 confidence 分级和稳定 fingerprint

## 开发

```bash
moon check     # 编译检查
moon test      # 运行测试（65 个用例 × 4 编译目标）
moon fmt       # 格式化
```

## 许可证

[MulanPSL-2.0](LICENSE)
