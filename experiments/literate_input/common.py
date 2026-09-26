"""Local-only helpers for the fixed compiler experiment."""

import gzip
import json
import os
from pathlib import Path
import subprocess


def paths():
    output = Path(os.environ.get(
        "LITERATE_ORACLE_OUTPUT", "/tmp/moon-audit-literate-oracle-20260926"
    ))
    output.mkdir(parents=True, exist_ok=True)
    versions = {
        "current": Path(os.environ.get(
            "CURRENT_MOON_HOME", "/tmp/moon-audit-upgrade-20260922/toolchain"
        )),
        "historical": Path(os.environ.get(
            "HISTORICAL_MOON_HOME", "/tmp/moon-audit-historical-2025/toolchain"
        )),
    }
    return output, versions


def run(home, command, *, timeout=30):
    env = dict(os.environ, MOON_HOME=str(home))
    env["PATH"] = str(home / "bin") + os.pathsep + env.get("PATH", "")
    return subprocess.run(
        command, capture_output=True, text=True, env=env, timeout=timeout
    )


def save(output, name, value):
    data = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    (output / (name + ".json.gz")).write_bytes(gzip.compress(data, mtime=0))


def package(directory, label):
    directory.mkdir(exist_ok=True)
    (directory / "moon.mod.json").write_text(
        '{"name":"test/literate","version":"0.1.0"}'
    )
    (directory / "moon.pkg.json").write_text("{}")
    (directory / "lib.mbt").write_text(
        "pub fn production() -> Int { 1 }\nfn private_f() -> Int { 2 }\n"
    )
    (directory / "doc.mbt.md").write_text(
        "```" + label + "\nfn f() -> Int { private_f() }\n```\n"
    )
