"""Record the base fence matrix against both installed compilers."""

from cases import base_cases
from common import paths, run, save


def main():
    output, versions = paths()
    cases = base_cases()
    records = []
    for version, home in versions.items():
        for index, (name, source) in enumerate(cases.items()):
            path = output / (str(index) + ".mbt.md")
            path.write_bytes(source.encode())
            for mode in ("plain", "doctests", "syncheck"):
                command = [
                    str(home / "bin" / "moonc"),
                    "syncheck" if mode == "syncheck" else "check",
                    str(path), "-error-format", "json",
                ]
                if mode != "syncheck":
                    command.append("-no-mi")
                if mode == "doctests":
                    command.append("-include-doctests")
                result = run(home, command)
                records.append(dict(
                    version=version, name=name, mode=mode, source=source,
                    command=command,
                    unsupported_command=(
                        version == "historical" and mode == "syncheck"
                    ),
                    returncode=result.returncode,
                    stdout=result.stdout, stderr=result.stderr,
                ))
    save(output, "results", records)
    print(f"Recorded {len(records)} observations; historical syncheck is excluded.")


if __name__ == "__main__":
    main()
