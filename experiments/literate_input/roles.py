"""Record parse contexts, package privacy, and compiler binary identities."""

import hashlib
import json

from common import package, paths, run, save


def main():
    output, versions = paths()
    records = []
    bodies = [
        ("expr", "unknown_name()"),
        ("let", "let x = unknown_name()"),
        ("test", "test { unknown_name() }"),
        ("incomplete", "fn f() -> Int {"),
    ]
    for version, home in versions.items():
        for label in ("mbt", "mbt check", "mbt test"):
            for name, body in bodies:
                path = output / "role.mbt.md"
                source = "```" + label + "\n" + body + "\n```\n"
                path.write_text(source)
                command = [str(home / "bin" / "moonc"), "check", str(path),
                           "-no-mi", "-error-format", "json"]
                result = run(home, command)
                records.append(dict(
                    version=version, label=label, bodyname=name, source=source,
                    returncode=result.returncode,
                    stdout=result.stdout, stderr=result.stderr,
                ))
            directory = output / ("package-" + version + "-" + label.replace(" ", "-"))
            package(directory, label)
            command = [str(home / "bin" / "moon"), "-C", str(directory), "check"]
            result = run(home, command, timeout=90)
            records.append(dict(
                version=version, label=label, bodyname="package_private",
                returncode=result.returncode,
                stdout=result.stdout, stderr=result.stderr,
            ))
    save(output, "roles", records)
    identities = {}
    for version, home in versions.items():
        compiler = home / "bin" / "moonc"
        result = run(home, [str(compiler), "-v"])
        result.check_returncode()
        identities[version] = dict(
            home=str(home),
            moonc_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
            version=result.stdout.strip(),
        )
    (output / "toolchains.json").write_text(json.dumps(identities, indent=2) + "\n")
    print(f"Recorded {len(records)} observations and both compiler identities.")


if __name__ == "__main__":
    main()
