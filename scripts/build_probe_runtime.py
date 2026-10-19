"""Build a synthetic public-CI Python runtime, with no host home/config mounts.

Only official runner image Python/stdlib/shared libraries are copied. This is
test tooling, never a production image builder or private repository input.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess


def build(destination: Path):
    if not destination.is_absolute() or destination.exists():
        raise ValueError("destination must be a new absolute directory")
    binary = Path("/usr/bin/python3")
    version = subprocess.check_output([str(binary), "-I", "-c",
                                       "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
                                      text=True).strip()
    if not re.fullmatch(r"3\.\d+", version):
        raise ValueError("unrecognized system Python")
    stdlib = Path("/usr/lib/python" + version)
    destination.mkdir(mode=0o755)
    (destination / "usr/bin").mkdir(parents=True)
    shutil.copy2(binary, destination / "usr/bin/python3")
    shutil.copytree(stdlib, destination / stdlib.relative_to("/"), symlinks=False,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    dependencies = set()
    for obj in [binary, *stdlib.rglob("*.so")]:
        result = subprocess.run(["/usr/bin/ldd", str(obj)], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            for match in re.findall(r"(?:=>\s+)?(/[^\s()]+)", line):
                path = Path(match)
                if not str(path).startswith(("/lib/", "/lib64/", "/usr/lib/")):
                    raise ValueError("unexpected dependency location")
                dependencies.add(path)
    for dependency in dependencies:
        target = destination / dependency.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dependency, target, follow_symlinks=True)
    for name in ("proc", "dev", "tmp", "work", "candidate"):
        (destination / name).mkdir()
    for path in destination.rglob("*"):
        if path.is_symlink():
            raise ValueError("runtime symlink refused")
    print("PUBLIC_SYNTHETIC_RUNTIME_CREATED=YES")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    build(parser.parse_args().destination)
