# Compatibility Matrix

| Analyzer backend | Target program backend | OS | Status |
|---|---|---|---|
| native | native | ubuntu | CI green |
| native | native | macos | CI green |
| native | native | windows | CI green |
| native | js | any | OK (AST-level, backend-independent) |
| native | wasm/wasm-gc | any | OK (AST-level, backend-independent) |
| wasm | any | any | OK (moon test --target all) |

Notes: AST-level analysis is target-backend-independent; .mbti canonical; CI covers check/build/fmt/info/test all targets.
