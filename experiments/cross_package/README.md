# 同模块跨包数据流验收（2026-09-26）

## 目标与边界

复用已存在的声明表与独立 IR，让目标编译器选择的同模块生产包在 mocket GET 内联回调范围内传递 String 参数/返回值。不是任意 `.mooncakes` 依赖、工作区全模块或完整 HTML/控制流分析。`.mbt.md` 开发任务保持删除。

本轮修复：仅按到达的回调/辅助函数体查询绑定；失败回调撤销所有新增 IR（含传递占位符）；基于官方位置与 SHA 建模 String 加法；解码简单字符串转义，数值转义明确报不支持。查询范围仍是整个到达的函数体，不是 CFG 路径敏感性；256 次绑定/4 并发/60 秒 worker 限制保持。

## 固定原生产包

[source-pin.json](source-pin.json) 固定 `mizchi/luna.mbt` 的 `874f0f34e77d6800cd9aab611b0a441d9d8d3ffe`。CI 校验归档及包内四文件 SHA，复制 `sol/src/internal/page_shell` 原字节，在隔离 `mizchi/sol` 调用方中测试；上游源码不提交进本仓库。

- 简单自建包：两跳、别名、同名伪转义、参数交换、String `+`；危险 3 路、安全/常量参数 2 路。
- 原生产 `app_container`：原样 `<div id="app">` 超出现有 HTML 上下文证明范围，危险输入和已编码输入均保留 `partial_dataflow`；返回 2，不能声称编码路径已安全。
- 原生产 `render_streaming_footer`：常量无来源路径；未知标签上下文仍不完整。
- 原生产 `escape_html_text`：首次构造调用未获得唯一绑定，函数还包含未支持的循环/分支；不能凭函数名推断净化。
- 原包测试和独立断言执行真实 HTML 输出，证明包装及转义的实际值；不构成该应用漏洞报告。

## 复现

```bash
python scripts/prepare_semantic_corpus.py --destination /tmp/moon-audit-models
python scripts/cross_package_test.py --analyzer /path/to/moon-audit \
  --toolchain /path/to/fixed-moon-home \
  --corpus /tmp/moon-audit-models/mocket \
  --luna-source /tmp/moon-audit-models/luna \
  --output /tmp/cross-package-acceptance.json
```

测试同时覆盖未建模外部调用/运算符、未支持转义、300 个无关调用、实际到达的绑定预算，以及失败辅助函数通过中间函数后被第二个回调再次调用。CI 从提取的交付包运行，保存 `cross-package-acceptance.json`。

最终本地结果、回归与三平台交付证据在本轮验收完成后登记。
