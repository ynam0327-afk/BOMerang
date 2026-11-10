import contextlib
import io
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "python-parser"))

from python_parser import PythonParser


class FakePyPIClient:
    def get_dependencies(self, package_name, version, extras=None):
        return []

    def get_available_versions(self, package_name):
        return []


def make_toml(count, poetry=False):
    if poetry:
        lines = [
            "[tool.poetry]",
            'name = "benchmark-project"',
            'version = "0.1.0"',
            "",
            "[tool.poetry.dependencies]",
            'python = ">=3.10"',
        ]
        lines += [
            f'benchmark-pkg-{i} = "==1.0.0"'
            for i in range(count)
        ]
    else:
        lines = [
            "[project]",
            'name = "benchmark-project"',
            'version = "0.1.0"',
            "dependencies = [",
        ]
        lines += [
            f'  "benchmark-pkg-{i}==1.0.0",'
            for i in range(count)
        ]
        lines.append("]")

    return "\n".join(lines) + "\n"


def benchmark(count, poetry=False, repeats=10):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pyproject.toml"
        path.write_text(
            make_toml(count, poetry),
            encoding="utf-8"
        )

        times = []

        for _ in range(repeats):
            parser = PythonParser(
                pypi_client=FakePyPIClient()
            )

            with contextlib.redirect_stdout(io.StringIO()):
                start = time.perf_counter()
                nodes = parser.parse(str(path))
                elapsed = time.perf_counter() - start

            if len(nodes) != count:
                print(
                    f"CHECK: expected={count}, "
                    f"actual={len(nodes)}"
                )
                return

            times.append(elapsed * 1000)

        name = "Poetry" if poetry else "PEP621"

        print(
            f"{name:7} | "
            f"{count:3} packages | "
            f"avg={statistics.mean(times):.3f}ms | "
            f"min={min(times):.3f}ms | "
            f"max={max(times):.3f}ms | PASS"
        )


print("=== BOMerang TOML Benchmark ===")

for poetry in [False, True]:
    for count in [10, 50, 100]:
        try:
            benchmark(count, poetry)
        except Exception as exc:
            print(
                f"{'Poetry' if poetry else 'PEP621'} "
                f"{count} packages | ERROR: {exc}"
            )
