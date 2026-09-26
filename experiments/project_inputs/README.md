# 项目输入与模块归属（2026-09-26）

本轮完善 MoonBit 项目通用输入的范围与配置兼容，不增加安全规则或数据流模型。它没有实现 `.mbt.md` 提取，也没有把目录遍历等同于工作区编译。

## 已实现契约

- 目录扫描发现 `.mbt`、`.mbt.md`、`.mbtx`；只对 `.mbt` 解析和运行规则。其余输入逐文件 `unsupported`，规则覆盖为空，exit 2，已有发现保留。`files_selected` 包含选中但不支持的文件，`files_scanned`/`files_parsed` 不包含它们。
- 编译计划已识别时，受支持和不支持的输入都受该计划约束；不会回退扫描其他后端。增量列表可列出三种扩展名。用户排除策略照常生效并记录在报告中。
- 模块身份从源码目录查找最近的 `moon.mod` / `moon.mod.json`，止于用户请求的扫描根，按目录缓存。嵌套业务模块不会继承外层标准库豁免；包 imports 仍仅从本目录包配置获取。
- 现代模块配置复用固定官方 `moonbitlang/moon_config@0.4.0`。旧模块和包配置支持 JSON 注释及尾随逗号，然后严格验证 JSON；不额外接受 JSON5 的单引号、无引号键、NaN 等语法。顶层重复键按解码后名称拒绝。非法配置报错，但保留语法发现。
- 标准库豁免仍是模块名称提示，不是可信来源认证；它只用于三条显式启用规则的降噪，逐规则 `gated_out` 保留原因。

## 为什么未直接提取 Markdown

[两代编译器实验](../literate_input/README.md)表明有效围栏标签随版本变化，`check` 和 `test` 解析上下文不同，编译计划还区分黑盒测试角色。简单字符串提取会丢掉选择依据和原始坐标，因此本轮先修复静默遗漏。

后续计划已按用户决定调整：删除 `.mbt.md` 检测及 Markdown 提取适配任务。上述实验保留为历史证据，现有未支持范围提示保留。当前重点是生产 `.mbt` 的模块/包归属、后端和编译角色表示、多模块验证与跨包分析，具体以 [TODO](../../TODO.md) 为准。

## 复测

`compare.py` 不联网、不重新选榜，读取此前导入的固定 24 项样本；缺失的归档保持未导入。它核对旧 `.mbt`/配置账本，并记录新增格式的逐文件 SHA-256；检查扫描前后源码未变、此前解析的文件和默认发现未改变。原始榜单实验不被覆盖。

```sh
python3 experiments/project_inputs/compare.py \
  --before /path/to/previous/moon-audit --after /path/to/current/moon-audit \
  --source-root /path/to/pinned/sources --output-dir /tmp/project-inputs
python3 experiments/project_inputs/config_oracle.py \
  --analyzer /path/to/current/moon-audit \
  --toolchain /path/to/2025/toolchain --toolchain /path/to/2026/toolchain \
  --output /tmp/config-oracle.json.gz
```

配置实验对两代真实编译器分别比较 JSONC、转义键、重复名称和超出 JSONC 的语法，保留所有命令结果与扫描报告。不用最新文档替代历史编译器行为。

本地与三平台最终验收记录在本目录结果及审查 PR 中；不完整率的变化是覆盖范围披露变化，不能解释为检测准确率变化。

## 本轮结果

[固定样本汇总](results-2026-09-26/summary.json)与逐项压缩报告：23 个已导入样本，此前 4,541 个可解析 `.mbt` 文件及 2 条默认发现完全一致，前后源码未变。18 个项目新披露 306 个未支持输入；完整范围从本轮前的 16 项变为 4 项，不完整从 7 项变为 19 项。原始 9 月 25 日的 15/8 统计仍保留，不与后续前端修复后的基线混用。

| 样本 | 普通扫描解析/选择 | 新披露未支持输入 | 意义 |
| --- | --- | --- | --- |
| core | 478/545 | 67 | 保留原 `.mbt` 结果，披露额外格式 |
| actrun | 62/63 | 1 | 同上 |
| QuickCheck | 34/48 | 14 | 已实现旧语法兼容继续有效，文档输入另行披露 |
| bitflow | 12/15 | 3 | 同上 |

这些是普通目录扫描范围；[编译计划复测](results-2026-09-26/verified-summary.json)单独保存 core/actrun 的目标后端范围，不能与目录计数混合。

[配置 oracle](config-oracle-2026-09-26.json.gz)的两代工具链共 18 项接受/拒绝对照通过。[独立复核](independent-review.json)在最终二进制上再次验证 12 项配置边界；复核发现的 JSONC 拒绝和重复名称问题均已修复。新增配置解析依赖的版本及 Apache-2.0 许可进入原生包。

本地全目标测试：wasm / wasm-gc / js 各 93 项，native 95 项；原生交付 36 项、CLI 22 项、进程监督 4 项通过。平台 CI 以审查 PR 的最终提交为准。
