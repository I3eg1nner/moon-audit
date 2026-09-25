"""Check the shipped syntax scanner against source compiled by a selected MoonBit toolchain.

The module's `version` is deliberately unrelated to the compiler version. The
selected executable, not moon.mod, supplies the compiler identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FILES = {
    'moon.mod': 'name = "review/version_compat"\nversion = "9.9.9"\npreferred_target = "native"\n',
    'moon.pkg': '',
    'danger.mbt': 'pub fn html(s : String) -> String {\n  s.replace(old="<", new="&lt;")\n}\n',
    'safe.mbt': 'pub fn html_safe(s : String) -> String {\n  s.replace_all(old="<", new="&lt;")\n}\n',
    'static_call.mbt': 'pub fn html_static(s : String) -> String {\n  String::replace(s, old="<", new="&lt;")\n}\n',
    'static_safe.mbt': 'pub fn html_static_safe(s : String) -> String {\n  String::replace_all(s, old="<", new="&lt;")\n}\n',
    'static_call_test.mbt': 'test "qualified and dot calls have the same behavior" {\n  assert_eq(html("<<"), html_static("<<"))\n  assert_eq(html_static("<<"), "&lt;<")\n}\n',
}
EXPECTED = [('danger.mbt', 2, 'CWE-116/replace-escaping')]
STATIC_EXPECTED = ('static_call.mbt', 2, 'CWE-116/replace-escaping')
# Accepted by all three tested moonc versions; parser 0.4.0 currently rejects it.
GAP_SOURCE = '''pub fn destructure() -> Unit {
  for (x, y) in [(1, 2)] {
    ignore(x)
    ignore(y)
  }
}
'''


def run(command, cwd):
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as error:
        return error


def verify(scanner: Path, project_moon: list[str]):
    version_result = run([*project_moon, 'version', '--all'], ROOT)
    if isinstance(version_result, Exception) or version_result.returncode:
        return {'status': 'toolchain_unavailable', 'detail': str(version_result)}
    version = version_result.stdout.strip()
    with tempfile.TemporaryDirectory(prefix='moon-audit-version-compat-') as directory:
        project = Path(directory)
        for name, content in FILES.items():
            (project / name).write_text(content, encoding='utf-8')
        digests = {name: hashlib.sha256(content.encode()).hexdigest() for name, content in FILES.items()}
        check = run([*project_moon, 'check', '--target', 'native'], project)
        if isinstance(check, Exception) or check.returncode:
            return {'status': 'compiler_rejected', 'project_toolchain': version,
                    'detail': str(check) if isinstance(check, Exception) else check.stderr or check.stdout}
        equivalence = run([*project_moon, 'test', '--target', 'native'], project)
        if isinstance(equivalence, Exception) or equivalence.returncode:
            return {'status': 'semantic_equivalence_failed', 'project_toolchain': version,
                    'detail': str(equivalence) if isinstance(equivalence, Exception) else equivalence.stderr or equivalence.stdout}
        scan = run([str(scanner), '--format', 'json', str(project)], ROOT)
        if isinstance(scan, Exception) or scan.returncode:
            return {'status': 'scanner_failed', 'project_toolchain': version,
                    'detail': str(scan) if isinstance(scan, Exception) else scan.stderr or scan.stdout}
        try:
            report = json.loads(scan.stdout)
        except ValueError as error:
            return {'status': 'scanner_protocol_error', 'project_toolchain': version, 'detail': str(error)}
        if any(hashlib.sha256((project / name).read_bytes()).hexdigest() != digest for name, digest in digests.items()):
            return {'status': 'source_changed', 'project_toolchain': version}
        observed = sorted((Path(item['file']).name, item['line'], item['rule_id'])
                          for item in report['findings'])
        portable_observed = [finding for finding in observed if finding[0] != 'static_call.mbt']
        static_observed = [finding for finding in observed if finding[0] == 'static_call.mbt']
        static_supported = static_observed == [STATIC_EXPECTED]
        base_passed = (portable_observed == EXPECTED and
                       static_observed in ([], [STATIC_EXPECTED]) and
                       report['errors'] == [] and report['files_scanned'] == 4 and
                       report.get('files_selected') == 4 and report.get('files_parsed') == 4 and
                       'parse-failures=0' in report['analysis_scope'])
        (project / 'new_syntax.mbt').write_text(GAP_SOURCE, encoding='utf-8')
        gap_check = run([*project_moon, 'check', '--target', 'native'], project)
        if isinstance(gap_check, Exception) or gap_check.returncode:
            gap_status = 'compiler_rejected'
            gap_errors = [str(gap_check) if isinstance(gap_check, Exception) else gap_check.stderr or gap_check.stdout]
        else:
            gap_scan = run([str(scanner), '--format', 'json', str(project)], ROOT)
            try:
                gap_report = json.loads(gap_scan.stdout) if not isinstance(gap_scan, Exception) else {}
            except ValueError:
                gap_report = {}
            gap_errors = [error.replace(str(project), '<PROJECT>') for error in gap_report.get('errors', ['scanner_protocol_error'])]
            gap_findings = sorted((Path(item['file']).name, item['line'], item['rule_id'])
                                  for item in gap_report.get('findings', []))
            if gap_findings == observed and len(gap_errors) == 1 and 'new_syntax.mbt' in gap_errors[0] and gap_scan.returncode == 2 and gap_report.get('files_selected') == 5 and gap_report.get('files_parsed') == 4:
                gap_status = 'compiler_accepted_parser_rejected'
            elif gap_findings == observed and gap_errors == [] and gap_scan.returncode == 0 and gap_report.get('files_selected') == 5 and gap_report.get('files_parsed') == 5:
                gap_status = 'supported'
            else:
                gap_status = 'unexpected_result'
        passed = base_passed and gap_status in {'compiler_accepted_parser_rejected', 'supported'}
        return {'schema': 'moon-audit.version-compat.v1',
                'status': 'verified' if passed and gap_status == 'supported' and static_supported else 'verified_limited' if passed else 'mismatch',
                'project_toolchain': version,
                'module_version': '9.9.9',
                'scanner_scope': report['analysis_scope'],
                'source_sha256': digests,
                'expected': EXPECTED, 'observed': observed,
                'equivalent_call_shape': {
                    'compiler_test': 'passed', 'expected': STATIC_EXPECTED,
                    'observed': static_observed,
                    'status': 'supported' if static_supported else
                              'compiler_accepted_parser_accepted_rule_missed' if not static_observed else 'unexpected_result',
                },
                'parse_errors': report['errors'], 'files_scanned': report['files_scanned'],
                'files_selected': report['files_selected'], 'files_parsed': report['files_parsed'],
                'new_syntax': {'status': gap_status, 'errors': gap_errors,
                               'source_sha256': hashlib.sha256(GAP_SOURCE.encode()).hexdigest()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', type=Path, default=ROOT / '_build/native/debug/build/src/main/main.exe')
    parser.add_argument('--project-moon-wrapper', type=Path, help='wrapper for the target project MoonBit toolchain')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    project_moon = [str(args.project_moon_wrapper), 'moon'] if args.project_moon_wrapper else ['moon']
    report = verify(args.scanner.resolve(), project_moon)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    else:
        print(rendered, end='')
    return 0 if report['status'] in {'verified', 'verified_limited'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
