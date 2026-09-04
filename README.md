# MoonBit Native Audit

MoonBit 原生安全审计工具，集成静态扫描、污点追踪与 LLM 深度审计。

## 为什么需要 moon-audit？

MoonBit 是一门年轻的语言，社区正在快速长出 Web 框架（mocket、crescent）、Markdown 渲染器（cmark）、前端框架（rabbita）——但安全工具还是空白。

Semgrep、CodeQL 不认识 `.mbt` 文件。手动审计当然可以，但你不可能盯着每一个 PR 看 `set_cookie()` 有没有加 `http_only=true`、`handle_cors()` 有没有限制 Origin。

moon-audit 用 MoonBit 官方 parser 直接解析 AST，在语法树上匹配 14 条 CWE 安全规则。它知道 mocket 的 `handle_cors()` 应该限制 Origin，知道 cmark 的 `render(safe=false)` 会吞掉 XSS 防护，也知道 `extern "js"` 文件里的 `.cast()` 不是 bug 而是 FFI 的日常——会自动跳过。

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

静态扫描的价值在于发现——它能在代码合入前低成本地扫出可疑模式，但不可避免地会有误报。moon-audit 通过三层手段控制误报：

1. **上下文过滤**：自动跳过 FFI 绑定、guard 校验、平台桩、unwrap 函数、标准库等已知安全上下文
2. **LLM 研判**（`llm-analyze`）：将静态发现 + 源码上下文发送给 LLM，逐条判定真/假阳
3. **深度审计**（`deep-audit`）：静态分析与 LLM 代码审查结合，生成可执行的审计脚本

在 5 个生态项目的 LLM 验证中，Web 规则精度达 90%+，mocket 项目达到 100% 精度（3/3 TP，0 FP）。目前所有提交 PR 的漏洞均经过验证确认。

## 快速开始

```bash
git clone https://github.com/I3eg1nner/moon-audit.git
cd moon-audit
moon install && moon build --target native

# 静态扫描
./moon-audit /path/to/project

# 全流程 pipeline（scan + 跨函数污点分析 + summary）
./moon-audit pipeline /path/to/project

# 调用图（M4 切片：闭世界 CHA + 去虚化索引）
moon-audit call-graph /path/to/project --details

# 增量扫描（只扫描变更文件，适合 CI）
git diff --name-only HEAD~1 > changed.txt
./moon-audit --changed-files changed.txt /path/to/project

# 生成 baseline（存量项目首次接入时，过滤已知告警）
./moon-audit generate-baseline -o .moon-audit-baseline.json /path/to/project
./moon-audit --baseline .moon-audit-baseline.json /path/to/project
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
| CWE-676/unsafe-call | 危险类型转换 (`unsafe_from_*`/`unsafe_new`) | 关闭 | 性能操作、guard body、`unsafe_to_char`/`unsafe_to_byte` 跳过 |
| CWE-248/panic-reachable | 库代码中 `abort("message")` 使调用者无法恢复 | 关闭 | 裸 panic、guard-else、平台桩、契约断言、`unwrap`/`get_exn` 函数跳过 |
| CWE-704/unsafe-cast | `.cast()` 绕过类型系统 | 关闭 | FFI 绑定文件跳过 |
| CWE-116/replace-escaping | `String::replace()` 仅替换首次出现，HTML 转义不完整 | 开启 | — |
| CWE-94/eval-extern | extern JS 中使用 `eval()`/`new Function()` | 关闭 | — |
| CWE-22/path-concat | 路径拼接可能导致目录穿越 | 关闭 | URL/route/URI 变量跳过 |

### Web 框架规则（Import 门控）

仅在项目引入相关框架时激活，从源头消除无关误报。

| 规则 ID | 描述 | 默认 | 门控框架 |
|---|---|---|---|
| CWE-79/cmark-unsafe | cmark 渲染 `safe=false`，原始 HTML 注入 | 开启 | cmark |
| CWE-79/inner-html | `inner_html()` 接收动态内容，DOM XSS | 关闭 | rabbita（常量参数跳过） |
| CWE-79/template-injection | HTML 响应字符串插值，反射型 XSS | 开启 | mocket/crescent |
| CWE-113/crlf-injection | HTTP 响应头注入动态值 | 开启 | 通用 |
| CWE-942/cors-credentials | CORS `credentials=true` 且未限制 Origin | 开启 | mocket/crescent |
| CWE-614/cookie-attrs | Cookie 缺少 HttpOnly/Secure/SameSite | 开启 | mocket/crescent |
| CWE-770/no-body-limit | 无请求体大小限制，DoS 风险 | 开启 | crescent |
| CWE-346/ws-origin | WebSocket 无 Origin 校验 | 开启 | mocket/crescent |

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

**默认不会导致 CI 失败**——moon-audit 默认以信息模式运行（exit 0），扫描结果仅上报到 GitHub Security 面板，不阻断构建和合并流程。只有显式设置 `fail-on-findings: 'true'` 时，发现漏洞才会让 CI 返回非零退出码。

```yaml
- uses: I3eg1nner/moon-audit@main
  with:
    fail-on-findings: 'true'    # 显式启用：发现漏洞时阻断 CI
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

## LLM 辅助降误报

静态扫描不可避免有误报。配置 `.env` 后可以用 LLM 逐条研判，自动区分真正漏洞和噪音。

**1. 配置 API Key**

```bash
cp .env.example .env
# 编辑 .env，填入你的 API 密钥
```

`.env` 支持多种 LLM 后端：

```bash
# Anthropic Claude（默认）
LLM_API_KEY=sk-ant-xxx
LLM_BASE_URL=https://api.anthropic.com/v1/messages
LLM_MODEL=claude-sonnet-4-20250514

# OpenAI 兼容 API
LLM_API_KEY=sk-xxx
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o

# 也支持 API_KEY / ANTHROPIC_API_KEY / Base_URL / Model 等变量名
```

**2. LLM 研判**

```bash
# 生成可执行的 Python 验证脚本，自动调用 LLM API
moon-audit llm-analyze --format script -o verify.py /path/to/project
python3 verify.py

# 或输出 JSON 格式的 prompt（手动调用）
moon-audit llm-analyze --format json /path/to/project
```

LLM 会对每条 finding 返回 `is_true_positive`、`confidence`、`explanation` 和 `remediation`。

**3. 深度审计**

```bash
# 静态分析 + LLM 代码审查结合，生成一键审计脚本
moon-audit deep-audit -o audit.py /path/to/project
python3 audit.py
```

`deep-audit` 会按安全相关性对源文件排序，将静态发现作为上下文发送给 LLM 做深度代码审查，合并去重后输出完整审计报告。

## 其他子命令

```bash
# PoC 验证脚本生成
moon-audit generate-poc -o poc.md /path/to/project

# 修复建议（含 Before/After 代码示例）
moon-audit remediate -o fixes.md /path/to/project

# 统计报告（按 CWE/OWASP 分类聚合）
moon-audit summary /path/to/project

# 查看所有规则及其默认状态
moon-audit list-rules
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
  .mbt 源码 → Import 分析 → AST 解析 → 14 条规则匹配 → 跨函数污点追踪 → 报告输出
                                                                         ↓（可选）
                                                              LLM 研判 / deep-audit / PoC 生成
```

1. **Import 分析**：解析 `moon.pkg`/`moon.mod` 依赖，构建 `ImportContext`，决定激活哪些 Web 规则
2. **AST 遍历**：每条规则实现 `IterVisitor` trait，遍历语法树匹配漏洞模式
3. **上下文过滤**：识别 FFI 绑定、guard 校验、平台桩、unwrap 函数等安全上下文，抑制误报
4. **跨函数污点追踪**：流敏感污点引擎生成函数摘要（参数→sink），调用点匹配摘要传播 source → sink 路径；`call-graph` 子命令提供闭世界 CHA 调用图（M4 将升级为指针分析驱动）
5. **输出**：Text / JSON / SARIF 2.1.0，每条 Finding 含 confidence 分级和稳定 fingerprint

## 开发

```bash
moon check     # 编译检查
moon test      # 运行测试（122 个用例 × 4 编译目标，--deny-warn 全绿）
moon fmt       # 格式化
```

## 许可证

[MulanPSL-2.0](LICENSE)
