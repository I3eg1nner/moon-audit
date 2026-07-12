# moon-audit 架构改进 TODO

基于 9 项架构审查，按可行性分阶段实施。

## Phase 1: 不改架构的立即改进

### 1.1 Finding 增加 confidence 字段
- [x] `Finding` 增加 `confidence: Confidence` 枚举 (High/Medium/Low)
- [x] 每条规则根据分析方式设定 confidence
  - High: CWE-116, CWE-94, CWE-79/cmark
  - Medium: CWE-942, CWE-614, CWE-79/inner-html, CWE-79/template, CWE-113, CWE-770
  - Low: CWE-22, CWE-346
- [x] JSON/SARIF/text 输出包含 confidence
- [x] 更新测试

### 1.2 SARIF 稳定 fingerprint
- [x] `Finding` 增加 `fingerprint: String`
- [x] 基于 rule_id + 代码片段 FNV-1a 哈希生成 (不依赖行号)
- [x] SARIF 输出 `partialFingerprints`
- [x] dedup_findings 改用 fingerprint

### 1.3 LLM/PoC 从默认 pipeline 拆出
- [x] pipeline 只保留 scan + taint + summary (3 阶段)
- [x] LLM/PoC/remediation 保留为独立子命令
- [x] pipeline 输出提示用户可选运行 llm-analyze / generate-poc / remediate

### 1.4 退出码反映扫描结果
- [x] 有 Error 级别 findings → exit 1
- [x] 参数解析错误 → exit 2
- [x] 无问题 → exit 0

### 1.5 工具定位更新
- [x] README 改为 "MoonBit 安全 linter，提供框架级规则包"
- [x] 工作原理图去掉 LLM/PoC，标注为可选辅助子命令

## Phase 2: 验证与推送

- [x] `moon check --target all`
- [x] `moon test --target all` (38/38 x 4 targets)
- [x] `moon fmt` 格式稳定
- [x] 推送到 GitHub (origin) — CI 通过 (ubuntu/macos/windows)
- [ ] 推送到 GitLink — SSH 服务端不可达，待恢复后重试

## Phase 3: 规则精度改进

### 3.1 修复 CWE-79/cmark 误报
- [x] cmark `render()` 默认已改为 `safe=true`，当前规则前提过时
- [x] 规则应仅在显式 `safe=false` 时报告
- [x] 扩展检测 `renderer()`/`xhtml_renderer()`/`from_doc()` 的 `safe=false`

### 3.2 CWE-770 改进
- [ ] mocket 无 body limit API，当前规则对该框架不可操作
- [ ] 根据框架实际 API 调整门控条件

### 3.3 CWE-942/CORS 检测增强
- [ ] 当前仅检测 `credentials=true`，漏检默认 `handle_cors()` 配置
- [ ] 应报告无显式 origin 限制的 CORS 配置

### 3.4 CWE-22 路径穿越检测增强
- [ ] 当前仅检测字符串拼接，漏检 `static_assets` + 通配符路由模式
- [ ] 需增加框架级路径穿越检测
