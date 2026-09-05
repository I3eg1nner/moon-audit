# 上游 PR 准备：`moonc build-package --dump-core-sexp`

## 动机（事实见 ../RESEARCH.md）

- moonbit-compiler 已开源（MoonBit Public Source License v1），MCore IR 定义于 `src/core.ml`
- `core_format.ml` 中**已存在** `dump_serialized_from_t : t array -> S.t`（.core → S 表达式），
  但没有任何 CLI 入口调用它（全库零调用方）
- `.core` 文件 = 魔数 + OCaml `Marshal` 二进制，与 OCaml 运行时耦合、无跨语言稳定性承诺，
  外部工具（静态分析、审计器）无法安全消费
- 官方 README 明言"开源编译器出于安全目的"——本选项正是服务该目标的最低成本设施

## 补丁内容（dump-core-sexp.patch）

两文件、+18/-1 行：

1. `src/driver_config.ml`：`Buildpkg_Opt` 新增 `dump_core_sexp : string ref` 与
   `-dump-core-sexp FILE` 选项（`Arg.Set_string`）
2. `src/moon0_main.ml`：`build_package` 的 `Core_End` 回调中，`.core` 写盘后若选项非空，
   `Core_format.import ~path` 读回 → `dump_serialized_from_t` → `S.print`（FILE=`-` 时）或
   `Io.write_s`（复用现成 `basic_io.ml` 的 S.t 写文件函数）

> 设计说明：任务原始设想 `--dump-core-sexp[=FILE]`（可选值）。OCaml stdlib `Arg`
> 不支持可选值参数（`String_opt` 会贪婪吞掉下一个 token，产生歧义），故采用
> **显式 `FILE` 参数 + `-` 表示 stdout** 的确定性语义。

## 静态核对（本环境无 opam/dune/ocaml，未做编译验证）

| 引用 | 签名 | 位置 |
|---|---|---|
| `Core_format.import` | `~(path : string) -> t array` | core_format.ml:240 |
| `Core_format.dump_serialized_from_t` | `t array -> S.t` | core_format.ml:253 |
| `Io.write_s` | `file -> S.t -> unit` | basic_io.ml:23 |
| `S.print` | `S.t -> unit`（stdout） | s.ml:149 |
| `Io` 别名 | moon0_main.ml 第 16 行已有 | — |
| match 臂类型 | 与 `Core_Start -> ()` 一致为 unit | — |

## 验证步骤（在有 OCaml 4.14.2 + dune 的环境）

```bash
git clone https://github.com/moonbitlang/moonbit-compiler && cd moonbit-compiler
git apply dump-core-sexp.patch
opam switch create 4.14.2 && opam install -y dune
dune build -p moonbit-lang
# 最小包验证（用 moon CLI 的 dry-run 得到完整参数）
mkdir -p /tmp/sexptest/src && cd /tmp/sexptest
printf 'name = "x"\nversion = "0.1.0"\n' > moon.mod
printf 'name = "x/src"\n' > src/moon.pkg 2>/dev/null || true
printf 'pub fn add(a : Int, b : Int) -> Int { a + b }\n' > src/lib.mbt
moon build --dry-run   # 复制输出的 moonc build-package 命令行
# 在命令行末尾追加： -dump-core-sexp /tmp/out.sexp
# 预期：/tmp/out.sexp 为可读 S 表达式，含 (program ...)、(types ...)、
#       (traits ...)、(methods ...)、(pkg_name "x/src")
```

## PR 描述草稿

**标题**：`feat(moonc): add --dump-core-sexp to build-package for external tooling`

**描述**：

> `Core_format.dump_serialized_from_t` already converts a serialized
> package (program + types + traits + method tables) into an
> S-expression, but it is not reachable from the CLI. The `.core` file
> format (magic + OCaml Marshal) cannot be safely consumed by external
> tools: it is tied to the OCaml runtime and has no cross-version
> stability promise.
>
> This adds `-dump-core-sexp FILE` to `moonc build-package` (`-` for
> stdout). When set, after the package is exported, moonc re-reads the
> serialized package and writes the S-expression form. This gives static
> analyzers, auditors, and debugging tooling a readable view of the
> typed core IR, which aligns with the project's stated goal of keeping
> the compiler source open for security measures.
>
> Implementation notes: 18 lines across two files; reuses
> `Core_format.import`, `Core_format.dump_serialized_from_t`, and
> `Io.write_s` as-is; no behavior change when the flag is unset.

## 风险与后续

- 未编译验证（本机无 OCaml 工具链）——静态核对了全部函数签名/类型/模块可见性
- sexp 输出格式随编译器版本演化（无稳定性承诺），消费者需 pin 版本——README 与 PR 均已注明
- 若合入：moon-audit 可增加可选的 `.core`-sexp 高保真摄取后端（见 ../PLAN.md 次路线）
