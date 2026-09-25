#!/usr/bin/env python3
"""Query official mocket declaration bindings; retain a String hover ambiguity counterexample."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

from validate_mocket import HERE, IGNORED, REVIEWED_COMMIT, fingerprint

# These positions are authored fixture coordinates, not a source frontend.
QUERIES = [
    ("route_registration", "security_probe", "peek-def", 8, "get", "index.mbt", "152:16-152:19"),
    ("request_field", "security_probe", "peek-def", 9, "req", "event.mbt", "3:3-3:6"),
    ("query_source", "security_probe", "peek-def", 9, "query", "request.mbt", "33:21-33:26"),
    ("map_get", "security_probe", "peek-def", 10, "get", "builtin/linked_hash_map.mbt", "269:31-269:34"),
    ("option_unwrap", "security_probe", "peek-def", 10, "unwrap_or", "builtin/option.mbt", "48:19-48:28"),
    ("string_helper", "security_probe", "peek-def", 11, "relay", "security_probe/probe.mbt", "2:4-2:9"),
    ("html_constructor", "security_probe", "peek-def", 12, "html", "responder.mbt", "92:8-92:12"),
    ("html_text_encoder", "security_probe", "peek-def", 16, "escape_html", "utils.mbt", "128:8-128:19"),
    ("html_actual_binding", "security_probe", "peek-def", 12, "rendered", "security_probe/probe.mbt", "11:9-11:17"),
    ("html_actual_hover", "security_probe", "hover", 12, "rendered", None, None),
    ("builtin_string_annotation", "security_probe", "peek-def", 11, "String", None, None),
    ("callback_parameter_hover", "security_probe", "hover", 9, "event", None, None),
    ("unknown_show_hover", "security_probe", "hover", 34, "value", None, None),
    ("overwritten_return_binding", "security_probe", "peek-def", 28, "result", "security_probe/probe.mbt", "26:13-26:19"),
    ("shadow_string_actual_hover", "shadow_probe", "hover", 6, "input", None, None),
    ("shadow_string_annotation", "shadow_probe", "peek-def", 5, "String", "shadow_probe/probe.mbt", "2:17-2:23"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mocket", type=Path, required=True)
    parser.add_argument("--reference-checkout", type=Path, required=True)
    parser.add_argument("--moon-wrapper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, wrapper = args.mocket.resolve(), args.moon_wrapper.resolve()
    archive = subprocess.check_output(["git", "-C", str(args.reference_checkout.resolve()), "archive", REVIEWED_COMMIT])
    tracked = set()
    with tarfile.open(fileobj=io.BytesIO(archive)) as snapshot:
        for member in snapshot.getmembers():
            if member.isfile():
                tracked.add(member.name)
                path = source / member.name
                if not path.is_file() or path.read_bytes() != snapshot.extractfile(member).read():
                    parser.error("source differs from reviewed commit: " + member.name)
    source_hashes = fingerprint(source, exclude_dependencies=True)
    extra = [name for name in source_hashes["files"] if name not in tracked and Path(name).suffix in {".mbt", ".mbti", ".c", ".h"}]
    if extra:
        parser.error("unexpected source outside reviewed commit: " + ", ".join(extra))
    if not (source / ".mooncakes").is_dir():
        parser.error("preinstalled frozen dependencies required")
    record = {
        "schema_version": 1,
        "purpose": "official_binding_probe_not_production_frontend_acceptance",
        "reviewed_commit": REVIEWED_COMMIT,
        "source_commit_verified": True,
        "source_fingerprint": source_hashes["sha256"],
        "dependency_fingerprints": {p.relative_to(source / ".mooncakes").as_posix(): fingerprint(p)["sha256"]
                                    for p in sorted((source / ".mooncakes").glob("*/*")) if p.is_dir()},
        "commands": [], "observations": [],
        "limits": [
            "Query coordinates are authored; AST extraction and lowering are not implemented here.",
            "Definition locations establish declaration identity, not full runtime dispatch targets.",
            "Hover String is identical for builtin String and a user-defined String implementing Show.",
            "No structured canonical type ID or generic substitution export was demonstrated.",
            "A return variable resolves to its binding, not its latest reaching assignment.",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="moon-audit-mocket-bindings-") as temp:
        work = Path(temp) / "mocket"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(*IGNORED))
        for package, template in [("security_probe", "probe.mbt.txt"), ("shadow_probe", "string_shadow.mbt.txt")]:
            dest = work / package
            dest.mkdir()
            shutil.copy2(HERE / "binding_fixture" / "moon.pkg.txt", dest / "moon.pkg")
            shutil.copy2(HERE / "binding_fixture" / template, dest / "probe.mbt")
        record["fixture_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in sorted((HERE / "binding_fixture").glob("*.txt"))}

        def run(arguments):
            start = time.monotonic()
            command = [str(wrapper), "moon", *arguments]
            result = subprocess.run(command, cwd=work, text=True, capture_output=True, timeout=60)
            entry = {"command": command, "exit_code": result.returncode, "stdout": result.stdout,
                     "stderr": result.stderr, "seconds": round(time.monotonic() - start, 4)}
            record["commands"].append(entry)
            return entry

        record["toolchain"] = run(["version", "--all"])["stdout"]
        checked = run(["check", "--frozen", "--target", "native", "security_probe", "shadow_probe", "--diagnostic-limit", "3"])
        if checked["exit_code"]:
            record["status"] = "compiler_check_failed"
        else:
            # A targeted moon check produces all_pkgs.json but no IDE metadata.
            # The first location query must allow the IDE to prepare its own metadata.
            bootstrap = run(["ide", "peek-def", "--json", "--target", "native", "--loc", "security_probe/probe.mbt:8:7"])
            record["ide_bootstrap_succeeded"] = bootstrap["exit_code"] == 0
            for name, package, kind, line, token, expected_file, expected_range in QUERIES:
                file = work / package / "probe.mbt"
                col = file.read_text().splitlines()[line - 1].index(token) + 1
                loc = f"{package}/probe.mbt:{line}:{col}"
                response = run(["ide", kind, "--json", "--no-check", "--target", "native", "--loc", loc])
                try:
                    value = json.loads(response["stdout"])
                except ValueError:
                    value = None
                item = {"name": name, "kind": kind, "query": loc, "command_index": len(record["commands"]) - 1,
                        "response": value, "exit_code": response["exit_code"]}
                if expected_file:
                    item["unique_expected_declaration"] = bool(response["exit_code"] == 0 and isinstance(value, list) and len(value) == 1
                        and value[0].get("path", "").endswith("/" + expected_file) and value[0].get("range") == expected_range)
                    if item["unique_expected_declaration"]:
                        target = Path(value[0]["path"])
                        text = target.read_text()
                        start_line = int(expected_range.split(":")[0])
                        item["declaration_source"] = {"path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                                                      "line": text.splitlines()[start_line - 1]}
                record["observations"].append(item)
            by_name = {item["name"]: item for item in record["observations"]}
            bound = all(item["unique_expected_declaration"] for item in record["observations"] if "unique_expected_declaration" in item)
            genuine = by_name["html_actual_hover"]["response"]
            shadow = by_name["shadow_string_actual_hover"]["response"]
            ambiguity = bool(isinstance(genuine, dict) and isinstance(shadow, dict)
                             and genuine.get("contents") == shadow.get("contents") == ["```moonbit\nString\n```"])
            record["required_declarations_unique"] = bound
            record["string_hover_ambiguity_reproduced"] = ambiguity
            record["canonical_string_type_fact_available"] = False
            record["status"] = "bindings_verified_type_boundary_restricted" if bound and ambiguity else "probe_failed"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: record.get(key) for key in ["status", "required_declarations_unique", "string_hover_ambiguity_reproduced", "canonical_string_type_fact_available"]}))
    return 0 if record["status"] == "bindings_verified_type_boundary_restricted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
