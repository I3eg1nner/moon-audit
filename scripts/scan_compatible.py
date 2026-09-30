#!/usr/bin/env python3
"""Run moon-audit with the target project's actual MoonBit toolchain.

A successful report means the selected compiler checked the project and the
analyzer parsed every selected source file. It does not certify unsupported
rules or all historical/future MoonBit syntax.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def command(argv, cwd, timeout):
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              encoding='utf-8', timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        return error


def compiler_file_plan(output: str, project: Path):
    """Read source operands from moon's own dry-run plan, never execute its lines."""
    source_files = set()
    unsupported_files = set()
    check_commands = 0
    for line in output.splitlines():
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if len(args) < 3 or Path(args[0]).name != 'moonc' or args[1] != 'check':
            continue
        check_commands += 1
        for operand in args[2:]:
            if not operand.endswith(('.mbt', '.mbt.md', '.mbtx')):
                continue
            path = (project / operand).resolve()
            try:
                relative = path.relative_to(project).as_posix()
            except ValueError:
                continue
            if relative.startswith('.mooncakes/'):
                continue
            if operand.endswith('.mbt'):
                source_files.add(relative)
            else:
                unsupported_files.add(relative)
    if not check_commands:
        return None
    return sorted(source_files), sorted(unsupported_files)


def scanner_policy_excludes(relative: str, configured: list[str]):
    path = Path(relative)
    if any(part.startswith('.') or part == '_build' for part in path.parts):
        return True
    if path.name.endswith(('_test.mbt', '_wbtest.mbt')):
        return True
    return any(part in configured for part in path.parts) or any(
        pattern.startswith('*') and path.name.endswith(pattern[1:]) for pattern in configured
    )


def scan(project: Path, scanner: Path, project_moon: list[str], target: str,
         scanner_args: list[str], timeout: int = 300):
    version = command([*project_moon, 'version', '--all'], project, timeout)
    if isinstance(version, subprocess.TimeoutExpired):
        return {'status': 'tool_timeout', 'detail': str(version)}
    if isinstance(version, Exception) or version.returncode:
        return {'status': 'toolchain_unavailable', 'detail': str(version)}
    identity = version.stdout.strip()
    checked = command([*project_moon, 'check', '--target', target], project, timeout)
    if isinstance(checked, subprocess.TimeoutExpired):
        return {'status': 'compiler_timeout', 'project_toolchain': identity, 'detail': str(checked)}
    if isinstance(checked, OSError):
        return {'status': 'toolchain_unavailable', 'project_toolchain': identity, 'detail': str(checked)}
    if checked.returncode:
        return {'status': 'compiler_rejected', 'project_toolchain': identity,
                'detail': str(checked) if isinstance(checked, Exception) else checked.stderr or checked.stdout}
    plan_result = command([*project_moon, 'check', '--target', target,
                           '--dry-run', '--verbose'], project, timeout)
    if isinstance(plan_result, subprocess.TimeoutExpired):
        return {'status': 'compiler_plan_timeout', 'project_toolchain': identity,
                'detail': str(plan_result)}
    if isinstance(plan_result, Exception) or plan_result.returncode:
        return {'status': 'compiler_plan_unavailable', 'project_toolchain': identity,
                'detail': str(plan_result) if isinstance(plan_result, Exception) else
                plan_result.stderr or plan_result.stdout}
    plan = compiler_file_plan(plan_result.stdout, project)
    if plan is None:
        return {'status': 'compiler_plan_unavailable', 'project_toolchain': identity,
                'detail': 'moon check --dry-run --verbose did not expose moonc check commands'}
    selected_files, unsupported_files = plan
    with tempfile.TemporaryDirectory(prefix='moon-audit-compiler-files-') as directory:
        changed = Path(directory) / 'selected.txt'
        changed.write_text(''.join(path + '\n' for path in selected_files), encoding='utf-8')
        result = command([str(scanner), '--format', 'json', *scanner_args,
                          '--changed-files', str(changed), str(project)], ROOT, timeout)
    if isinstance(result, subprocess.TimeoutExpired):
        return {'status': 'scanner_timeout', 'project_toolchain': identity, 'detail': str(result)}
    if isinstance(result, Exception):
        return {'status': 'scanner_unavailable', 'project_toolchain': identity, 'detail': str(result)}
    try:
        report = json.loads(result.stdout)
    except ValueError:
        return {'status': 'scanner_protocol_error', 'project_toolchain': identity,
                'exit_code': result.returncode, 'detail': result.stderr or result.stdout}
    manifest = report.get('analysis_manifest', {})
    files = manifest.get('files', [])
    parsed_files = set()
    for item in files:
        if item.get('status') != 'parsed':
            continue
        try:
            parsed_files.add(Path(item['path']).resolve().relative_to(project).as_posix())
        except ValueError:
            continue
    configured = manifest.get('selection', {}).get('configured_excludes', [])
    excluded_files = sorted(path for path in selected_files
                            if scanner_policy_excludes(path, configured))
    expected_files = set(selected_files) - set(excluded_files)
    missing_files = sorted(expected_files - parsed_files)
    extra_files = sorted(parsed_files - expected_files)
    selection = {'source': 'moon check --dry-run --verbose', 'target': target,
                 'compiler_files': selected_files,
                 'compiler_files_excluded_by_scanner_policy': excluded_files,
                 'unsupported_compiler_file_formats': unsupported_files,
                 'scanner_parsed_files': sorted(parsed_files),
                 'compiler_files_not_parsed': missing_files,
                 'scanner_files_not_in_compiler_plan': extra_files}
    base = {'schema': 'moon-audit.compatible-scan.v2',
            'project_toolchain': identity, 'target': target,
            'file_selection': selection, 'scan': report}
    if result.returncode or report.get('errors'):
        return {**base, 'status': 'scanner_incomplete', 'exit_code': result.returncode}
    if not selected_files or missing_files or extra_files or unsupported_files:
        return {**base, 'status': 'scope_incomplete'}
    return {**base, 'status': 'compiled_and_parsed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project', type=Path)
    parser.add_argument('--scanner', type=Path, default=ROOT / '_build/native/debug/build/src/main/main.exe')
    parser.add_argument('--project-moon-wrapper', type=Path, help='wrapper that selects the project MoonBit toolchain')
    parser.add_argument('--target', default='native', choices=['native', 'js', 'wasm', 'wasm-gc'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=300)
    args = parser.parse_args()
    project = args.project.resolve()
    if not project.is_dir():
        parser.error(f'project directory does not exist: {project}')
    project_moon = [str(args.project_moon_wrapper), 'moon'] if args.project_moon_wrapper else ['moon']
    if args.timeout_seconds < 1:
        parser.error('--timeout-seconds must be positive')
    report = scan(project, args.scanner.resolve(), project_moon, args.target, [], args.timeout_seconds)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end='')
    return 0 if report['status'] == 'compiled_and_parsed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
