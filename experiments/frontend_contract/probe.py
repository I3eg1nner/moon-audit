"""Probe official semantic tooling on compiled fixtures; this is not a frontend.

No AST taint, inference, lowering, or production scanner is involved. Positions
and expected declaration locations are specified by the fixture author.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

FILES = {
    'moon.mod': 'name = "review/frontend_contract"\npreferred_target = "native"\n',
    'moon.pkg': 'import { "review/frontend_contract/left" @left, "review/frontend_contract/right" @right }\n',
    'left/moon.pkg': '',
    'right/moon.pkg': '',
    'left/lib.mbt': 'pub fn choose(value : String) -> String { value }\n',
    'right/lib.mbt': 'pub fn choose(value : String) -> String { ignore(value); "safe" }\n',
    'probe.mbt': '''pub struct Box { mut value : String }
fn fill(first : Box, second : Box) -> Unit {
  first.value = "dirty"
  second.value = "safe"
}
pub fn alias_case() -> String {
  let box = Box::{value: "initial"}
  fill(box, box)
  box.value
}
pub fn shadow_case() -> String {
  let box = Box::{value: "outer"}
  let old = box
  let box = Box::{value: "inner"}
  box.value = "new"
  old.value
}
pub fn cross_package(value : String) -> String {
  let a = @left.choose(value)
  @right.choose(a)
}
fn Box::read(self : Box) -> String { self.value }
pub fn method_case(box : Box) -> String { box.read() }
trait Render { render(Self) -> String }
impl Render for Box with fn render(self) -> String { self.value }
fn[T : Render] generic_wrap(value : T) -> String { value.render() }
pub fn generic_case(box : Box) -> String { generic_wrap(box) }
pub fn callback_case(f : (String) -> String, value : String) -> String { f(value) }
fn fallback() -> String { "fallback" }
fn with_default(value? : String = fallback()) -> String { value }
pub fn default_case() -> String { with_default() }
suberror Boom { Boom }
fn write_then_raise(box : Box) -> Unit raise Boom { box.value = "dirty"; raise Boom }
pub fn error_case(box : Box) -> String {
  try { write_then_raise(box); "normal" } catch { Boom => box.value }
}
''',
}


def position(fragment: str, token: str, file: str = 'probe.mbt') -> tuple[str, int, int]:
    """Locate only a predeclared fixture query, never parse a user program."""
    lines = FILES[file].splitlines()
    hits = [(i + 1, line) for i, line in enumerate(lines) if fragment in line]
    if len(hits) != 1:
        raise ValueError((fragment, hits))
    line, text = hits[0]
    return file, line, text.index(token) + 1


# A definition lookup denotes a declaration, not a runtime target set.
QUERIES = [
    ('direct_call', 'peek-def', '  fill(box, box)', 'fill', ('probe.mbt', 2)),
    ('actual_type', 'hover', '  fill(box, box)', 'box', None),
    ('field_declaration', 'peek-def', '  box.value', 'value', ('probe.mbt', 1)),
    ('shadow_inner', 'peek-def', '  box.value = "new"', 'box', ('probe.mbt', 14)),
    ('shadow_outer', 'peek-def', '  let old = box', 'box', ('probe.mbt', 12)),
    ('package_left', 'peek-def', '  let a = @left.choose(value)', 'choose', ('left/lib.mbt', 1)),
    ('package_right', 'peek-def', '  @right.choose(a)', 'choose', ('right/lib.mbt', 1)),
    ('method', 'peek-def', 'pub fn method_case', 'read', ('probe.mbt', 22)),
    ('generic_trait', 'peek-def', 'fn[T : Render] generic_wrap', 'render', ('probe.mbt', 24)),
    ('generic_call', 'hover', 'pub fn generic_case', 'generic_wrap', None),
    ('callback', 'peek-def', 'pub fn callback_case', 'f(value)', ('probe.mbt', 28)),
    ('default_call', 'peek-def', 'pub fn default_case', 'with_default', ('probe.mbt', 30)),
    ('error_call', 'hover', '  try { write_then_raise', 'write_then_raise', None),
    ('aliased_actual_references', 'find-references', '  let box = Box::{value: "initial"}', 'box', None),
]


def run_probe(moon: str, work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=False)
    for name, source in FILES.items():
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding='utf-8')
    records = []

    def command(args: list[str]) -> dict:
        started = time.monotonic()
        try:
            p = subprocess.run([moon, *args], cwd=work, capture_output=True,
                               text=True, encoding='utf-8', timeout=45)
            item = {'command': ['moon', *args], 'exit_code': p.returncode,
                    'stdout': p.stdout, 'stderr': p.stderr}
        except subprocess.TimeoutExpired as error:
            item = {'command': ['moon', *args], 'exit_code': None, 'timeout': True,
                    'stdout': str(error.stdout or ''), 'stderr': str(error.stderr or '')}
        item['seconds'] = round(time.monotonic() - started, 4)
        records.append(item)
        return item

    def decode(record: dict) -> tuple[bool, object]:
        if record['exit_code'] != 0:
            return False, None
        try:
            return True, json.loads(record['stdout'])
        except ValueError:
            return False, None

    version = command(['version', '--all'])
    check = command(['check', '--target', 'native'])
    result = {'schema': 'moon-audit.frontend-capability-probe.v1',
              'target': 'native', 'version': version['stdout'],
              'source_files': FILES,
              'source_sha256': {n: hashlib.sha256(s.encode()).hexdigest() for n, s in FILES.items()},
              'commands': records, 'observations': [],
              'compiler_check_passed': check['exit_code'] == 0,
              'solver_input_ready': False,
              'limits': ['Fixture positions are authored, not discovered by a source frontend.',
                         'Definition locations are not complete runtime call targets.',
                         'No typed IR, CFG, heap effect, argument binding or error-edge export demonstrated.',
                         'No production scanner or core implementation is changed.']}
    if not result['compiler_check_passed']:
        return result
    # No --no-check query is issued until the fixed source snapshot is checked.
    for name, kind, fragment, token, expected in QUERIES:
        if name == 'field_declaration':
            file, line, col = 'probe.mbt', 9, 7
        else:
            file, line, col = position(fragment, token)
        raw = command(['ide', kind, '--loc', f'{file}:{line}:{col}', '--target', 'native', '--no-check', '--json'])
        valid_json, value = decode(raw)
        observed = {'name': name, 'query': f'{file}:{line}:{col}',
                    'command_index': len(records) - 1, 'valid_json': valid_json,
                    'response': value, 'expected_declaration': expected}
        if expected:
            observed['matches_expected_declaration'] = valid_json and isinstance(value, list) and any(
                isinstance(v, dict) and Path(v.get('path', '')).as_posix().endswith('/' + expected[0])
                and str(v.get('range', '')).startswith(str(expected[1]) + ':') for v in value)
        expected_hover = {
            'actual_type': 'Box',
            'generic_call': 'fn[T : Render] generic_wrap(value : T) -> String',
            'error_call': 'fn write_then_raise(box : Box) -> Unit raise Boom',
        }.get(name)
        if expected_hover:
            observed['expected_display_text'] = expected_hover
            observed['matches_expected_display'] = valid_json and isinstance(value, dict) and any(
                expected_hover in entry for entry in value.get('contents', []) if isinstance(entry, str))
        if name == 'aliased_actual_references':
            observed['matches_expected_references'] = valid_json and isinstance(value, list) and {
                v.get('range') for v in value if isinstance(v, dict)
            } == {'8:8-8:11', '8:13-8:16', '9:3-9:6'}
        observed['contract_satisfied'] = valid_json and all(v for k, v in observed.items() if k.startswith('matches_expected_'))
        result['observations'].append(observed)
        print(name, json.dumps(observed, ensure_ascii=False), flush=True)
    symbols = command(['ide', 'gen-symbols', '--target', 'native', '--no-check'])
    path = work / 'symbols.jsonl'
    result['symbol_index'] = [json.loads(line) for line in path.read_text().splitlines()] if symbols['exit_code'] == 0 and path.exists() else None
    result['symbol_index_limits'] = {
        'observed_keys': sorted({key for symbol in result['symbol_index'] or [] for key in symbol}),
        'tag_is_not_unique': len({symbol.get('tag') for symbol in result['symbol_index'] or []}) < len(result['symbol_index'] or []),
        'only_current_package_indexed': all(symbol.get('pkg') == 'review/frontend_contract' for symbol in result['symbol_index'] or []),
    }
    result['source_unchanged'] = all((work / n).read_text() == s for n, s in FILES.items())
    result['lookup_checks_passed'] = all(o['contract_satisfied'] for o in result['observations'])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--moon', default='moon', help='Moon executable in the selected toolchain')
    parser.add_argument('--work-dir', type=Path, required=True, help='New, nonexistent directory for fixtures')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    report = run_probe(args.moon, args.work_dir.resolve())
    report['producer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Report:', args.report)
    print('Solver input ready:', report['solver_input_ready'])
    if not report['compiler_check_passed']:
        return 2
    return 0 if report.get('source_unchanged') and report.get('lookup_checks_passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
