# 14 条语法规则独立审计（2026-09-25）

## 裁决

仅建议默认保留 `CWE-116/replace-escaping` 和 `CWE-79/cmark-unsafe` 两条有限语法提示。其他 12 条保留为显式选择的人工审查辅助。**全部 14 条仍为 `syntax_hint`，没有一条因此成为已证实漏洞。**

[decisions.json](decisions.json) 是逐条裁决：触发形状、可匹配调用形式、真实证据、局限、默认策略和建议文案。裁决不修改扫描器实现；生产能力登记应以这里的证据修订描述和默认策略。

## 实验结果

| 矩阵 | 结果 | 能证明什么 |
|---|---:|---|
| 14 条规则形状 / 控制 / 同名反例，另加两个漏报反例 | 44/44 编译和观察符合预期 | 规则实际匹配边界，以及已知误报/漏报 |
| mocket 0.9.1 真实 API | 8/8 编译和观察符合预期 | cookie、HTML responder、CORS 调用形状有效 |
| cmark 0.4.8 真实 API | 3/3 编译和观察符合预期 | render 的 safe=false、true、默认调用有效 |
| crescent 0.11.0 真实源码 | 4/4 未核实 | 固定编译器拒绝该库旧 lexscan API；不能声称调用编译通过 |
| builtin String 和 JavaScript FFI 运行时 oracle | native 2/2，JS 2/2 | 首次/全部替换语义；JS 注释不执行 eval |
| 统一登记后的新二进制形状复验 | 44/44 | 显式选择规则保持原有可审查的匹配边界 |
| 能力登记 / 默认策略 / 实际执行一致性 | 98/98 | 14 条规则 × 7 种选择、门控、严重度模式 |

这里的“符合预期”**包括重现误报、漏报**，不是安全准确率。`dangerous_shape` 是原规则宣称的危险形状；对合成 API 不赋予真实安全含义。每个 fixture 的证据类型在 JSON 中单独记录。

真实库矩阵的完整验收返回非零（11/15，4 个 crescent 编译被拒绝），这一事实保留在证据中。相应规则默认停用，不能通过修改被分析库或冒充 API 来掩盖版本不兼容。

## 关键反例

- 本地无害包的名字带 `mocket_cmark_rabbita_crescent` 就能满足导入门控；导入名称子串不证明 API 身份。
- 无害 `Dummy.replace`、`render`、`set_header`、`unsafe_cast`、`cast` 等同名 API 可编译且会命中规则。
- `CWE-94` 会匹配 JS 注释中的 `eval(input)`。运行时 oracle 证实该函数只是返回输入。
- 真实 mocket 的 `secure=false, http_only=false, same_site=SameSiteNone` 不告警；当前规则只检查标签存在。
- 真实 mocket 的可信常量经局部变量插值仍告警；规则未建立输入来源或返回响应路径。
- builtin `abort` 在可达的 `guard ... else` 内被过滤；无害局部 `abort` 函数会被误报。
- crescent 源码的限制配置位于 `NativeServeOptions(max_request_body_bytes=...)`，规则只看直接标签；该库的编译验证受旧 lexscan 阻塞，仅作为源码审查结论。
- 原 CORS 描述把 `credentials=true` 与 `origin="*"` 当作任意网站可读取认证响应的证明，结论不成立。浏览器的凭证模式为 `include` 时，通配来源不能通过 CORS 响应共享检查。[WHATWG Fetch](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)

rabbita `inner_html` 的真实源码赋值 `innerHTML` 已读取（0.15.5，html/attrs.mbt 与 svg/attrs.mbt），但本轮未取得库级编译或浏览器执行证据，因此仍标记未核实。WebSocket 升级名称与 `unsafe_cast`/`cast` 等规则没有核实到对应的当前真实库危险 API，不能把合成反例当成正向证明。

## 复现

以下 Python 仅用于开发验收，不是用户运行扫描器的依赖。全部实验在 `/tmp` 副本内进行，fixture 使用 `.mbt.txt` 后缀以免被本项目构建收集。

```bash
python3 experiments/rule_audit/validate.py \
  --moon-wrapper /tmp/moon-audit-upgrade-20260922/with-toolchain \
  --analyzer _build/native/release/build/src/main/main.exe \
  --output /tmp/rule-shape-matrix.json

python3 experiments/rule_audit/validate_libraries.py \
  --moon-wrapper /tmp/moon-audit-upgrade-20260922/with-toolchain \
  --analyzer _build/native/release/build/src/main/main.exe \
  --mocket /tmp/moon-audit-upgrade-20260922/compiled-corpus-mocket \
  --crescent /tmp/moon-audit-upgrade-20260922/compiled-corpus-crescent \
  --cmark /tmp/moon-audit-cmark-chain-20260925/cmark \
  --output /tmp/rule-library-matrix.json

python3 experiments/rule_audit/validate_runtime.py \
  --moon-wrapper /tmp/moon-audit-upgrade-20260922/with-toolchain \
  --output /tmp/rule-runtime-oracle.json
```

新登记的最终 98 项一致性验收覆盖默认选择、`--rule`、配置启用、配置停用、缺少库导入提示、标准库模块门控、显式严重度降级；同时核对报告能力登记与逐文件覆盖中的完整 14 条规则、两个默认启用项和 `syntax_hint` 证据类型。它不把重现语法匹配当作安全准确率。

```bash
python3 experiments/rule_audit/validate_registry.py \
  --analyzer _build/native/release/build/src/main/main.exe \
  --output /tmp/rule-registry-acceptance.json
```

`shape-matrix-final-2026-09-25.json` 和 `registry-acceptance-final-2026-09-25.json` 保存最终实现的独立复验，包含二进制指纹。报告中的调用形式也逐条对照独立审计裁决。

复核发现 CWE-942 曾忽略用户严重度配置、硬编码为 Error；`registry-severity-regression-2026-09-25.json` 留存该缺陷的 97/98 观察。修复后达到 98/98。较早的 `*-registry-*` / `registry-acceptance-2026-09-25.json` 记录仅证明修复前的 44 / 84 项阶段验收，不能代替最终证据。

审计保存了原生扫描器 SHA256、编译器版本、fixture SHA256 和真实库源文件 SHA256。`shape-matrix-2026-09-25.json` 与 `real-library-matrix-2026-09-25.json` 是策略修订前的观察；生产改动后应使用新二进制再跑矩阵，而不是重写历史观察。

依赖副本须先准备好；真实库脚本始终 `--frozen`，不安装或更新依赖。mocket 与 cmark 固定源码/依赖来源还可对照 `../security_chain` 的运行时和绑定实验收据。编译范围是新添 probe 包及其依赖，不声称编译了库内所有示例和基准程序。
