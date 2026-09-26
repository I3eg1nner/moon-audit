#!/usr/bin/env python3
"""Compare recorded Moon compiler plans with moon-audit compilation units.

Independent, read-only acceptance oracle for the 2025/2026 .mbt fixtures in this
experiment. It is not a general Moon configuration parser: module identity must
use JSON with a unique literal name, or one simple unescaped name assignment in
moon.mod. Unknown options/configuration forms fail instead of being guessed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
from collections import Counter

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate configuration key: {key}')
        result[key] = value
    return result


def module_name(root):
    modern = root / 'moon.mod'
    if modern.exists():
        source = modern.read_text(encoding='utf-8')
        # Deliberately limited to the simple literal form in these fixtures.
        assignments = re.findall(r'^\s*name\s*=([^\n]*)$', source, re.MULTILINE)
        require(len(assignments) == 1, f'unsupported module name form: {modern}')
        match = re.fullmatch(r'\s*"([A-Za-z0-9_./-]+)"\s*', assignments[0])
        require(match is not None, f'unsupported module name literal: {modern}')
        return match.group(1)
    legacy = root / 'moon.mod.json'
    data = json.loads(legacy.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
    require(isinstance(data, dict), f'non-object module configuration: {legacy}')
    name = data.get('name')
    require(isinstance(name, str) and name, f'invalid module name: {legacy}')
    return name


def plan_identities(text, root):
    observations = json.loads((HERE / 'official-plan-observations.json').read_text())
    arity = observations['argument_arity']['current']
    values, switches = set(arity['value']), set(arity['noarg'])
    # Recognized arity is not proof that original disk bytes are the input.
    rejected = {'-patch-file', '-replace-name', '-replace-content', '-single-file',
                '-cfg', '-check-mi', '-ignore-import-declaration',
                '-help', '--help', '-warn-help'}
    result = []
    commands = 0
    for line_number, line in enumerate(text.splitlines(), 1):
        words = shlex.split(line)
        if len(words) < 2:
            continue
        executable = words[0].replace('\\', '/').split('/')[-1]
        if executable not in {'moonc', 'moonc.exe'} or words[1] != 'check':
            continue
        commands += 1
        flags, inputs, index = {}, [], 2
        while index < len(words):
            word = words[index]
            index += 1
            require(word not in rejected, f'unsupported input semantics: {word}')
            if word in values:
                require(index < len(words), f'missing value for {word}')
                value = words[index]
                index += 1
                if word == '-doctest-only':
                    inputs.append((str((root / value).resolve()), 'doctest_only'))
                else:
                    flags.setdefault(word, []).append(value)
            elif word in switches:
                require(word not in flags, f'duplicate switch: {word}')
                flags[word] = True
            else:
                require(not word.startswith('-'), f'unknown option on line {line_number}: {word}')
                require(word.endswith('.mbt'), f'unsupported source operand: {word}')
                inputs.append((str((root / word).resolve()), 'source'))
        inputs = [item for item in inputs
                  if Path(item[0]).is_relative_to(root)
                  and '.mooncakes' not in Path(item[0]).relative_to(root).parts]
        if not inputs:
            continue

        def one(flag, default=None):
            found = flags.get(flag, [] if default is None else [default])
            require(isinstance(found, list) and len(found) == 1,
                    f'missing or duplicate identity flag: {flag}')
            return found[0]

        package = one('-pkg')
        target = one('-target')
        blackbox, whitebox = bool(flags.get('-blackbox-test')), bool(flags.get('-whitebox-test'))
        require(not (blackbox and whitebox), 'conflicting compilation roles')
        role = 'blackbox_test' if blackbox else 'whitebox_test' if whitebox else 'production'
        if flags.get('-include-doctests') or any(mode == 'doctest_only' for _, mode in inputs):
            require(blackbox and flags.get('-include-doctests'), 'invalid doctest context')
        sources = [value[len(package) + 1:] for value in flags.get('-pkg-sources', [])
                   if value.startswith(package + ':')]
        require(len(sources) == 1, f'missing or ambiguous package source: {package}')
        module_root = (root / one('-workspace-path')).resolve()
        package_root = (root / sources[0]).resolve()
        kind = one('-pkg-type', 'executable' if flags.get('-is-main') else 'library')
        result.append((str(module_root), module_name(module_root), package,
                       str(package_root), kind, target, role, tuple(sorted(inputs))))
    require(commands > 0, 'plan contains no moonc check command')
    return sorted(result)


def report_identities(units):
    return sorted((unit['module_root'], unit['module_name'], unit['package_name'],
                   unit['package_root'], unit['package_kind'], unit['target'], unit['role'],
                   tuple(sorted((item['path'], item['mode']) for item in unit['inputs'])))
                  for unit in units)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, required=True)
    args = parser.parse_args()
    root = args.project_root.resolve()
    expected = plan_identities(args.plan.read_text(encoding='utf-8'), root)
    report = json.loads(args.report.read_text(encoding='utf-8'))
    units = report['project_verification']['compilation_units']
    actual = report_identities(units)
    require(expected == actual, 'compilation identities differ:\n' + json.dumps(
        {'expected': expected, 'actual': actual}, indent=2))
    print(json.dumps({'identity_matches_official_plan': True,
                      'units': len(units),
                      'roles': dict(Counter(unit['role'] for unit in units))}, sort_keys=True))


if __name__ == '__main__':
    main()
