"""Record legacy labels, Markdown containers, and package compiler roles."""

from cases import extended_cases
from common import package, paths, run, save


def main():
    output, versions = paths()
    records = []
    for version, home in versions.items():
        for index, (name, source) in enumerate(extended_cases().items()):
            path = output / ("x" + str(index) + ".mbt.md")
            path.write_bytes(source.encode())
            command = [str(home / "bin" / "moonc"), "check", str(path),
                       "-no-mi", "-error-format", "json"]
            result = run(home, command)
            records.append(dict(
                version=version, name=name, source=source, command=command,
                returncode=result.returncode,
                stdout=result.stdout, stderr=result.stderr,
            ))
    save(output, "extended", records)
    directory = output / "package"
    package(directory, "mbt check")
    for version, home in versions.items():
        for mode in ("plan", "actual"):
            command = [str(home / "bin" / "moon"), "-C", str(directory), "check"]
            if mode == "plan":
                command.append("--dry-run")
            result = run(home, command, timeout=90)
            save(output, version + "-package-" + mode, dict(
                cmd=command, returncode=result.returncode,
                stdout=result.stdout, stderr=result.stderr,
            ))
    print(f"Recorded {len(records)} observations and four package command records.")


if __name__ == "__main__":
    main()
