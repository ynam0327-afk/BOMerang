import contextlib
import io
import statistics
import sys
import tempfile
import time
from pathlib import Path

from packaging.requirements import Requirement

sys.path.insert(0, str(Path.cwd() / "python-parser"))
from python_parser import PythonParser


class FakePyPIClient:
    def __init__(self, depth):
        self.depth = depth

    def get_dependencies(self, package_name, version, extras=None):
        if package_name == "parent":
            return [Requirement("child-1==1.0.0")]

        if package_name.startswith("child-"):
            index = int(package_name.split("-")[-1])

            if index < self.depth:
                return [
                    Requirement(
                        f"child-{index + 1}==1.0.0"
                    )
                ]

        return []

    def get_available_versions(self, package_name):
        return ["1.0.0"]


def benchmark(depth, repeats=10):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "requirements.txt"
        path.write_text(
            "parent==1.0.0\n",
            encoding="utf-8"
        )

        times = []
        counts = []

        for _ in range(repeats):
            parser = PythonParser(
                pypi_client=FakePyPIClient(depth)
            )

            with contextlib.redirect_stdout(io.StringIO()):
                start = time.perf_counter()
                nodes = parser.parse(str(path))
                elapsed = time.perf_counter() - start

            times.append(elapsed * 1000)
            counts.append(len(nodes))

        expected = depth + 1
        passed = all(n == expected for n in counts)

        print(
            f"Depth={depth:2} | "
            f"expected={expected:2} | "
            f"actual={counts} | "
            f"avg={statistics.mean(times):.3f}ms | "
            f"median={statistics.median(times):.3f}ms | "
            f"{'PASS' if passed else 'CHECK'}"
        )


print("=== BOMerang Recursive Dependency Benchmark ===")

for depth in [1, 3, 5, 10]:
    benchmark(depth)
