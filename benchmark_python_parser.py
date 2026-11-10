import sys
import time
import statistics
import tempfile
import contextlib
import io
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "python-parser"))

from python_parser import PythonParser


class FakePyPIClient:
    def get_dependencies(self, package_name, version, extras=None):
        return []

    def get_available_versions(self, package_name):
        return []


def benchmark(count, repeats=5):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "requirements.txt"

        path.write_text(
            "\n".join(
                f"benchmark-pkg-{i}==1.0.0"
                for i in range(count)
            ) + "\n",
            encoding="utf-8"
        )

        times = []
        node_counts = []

        for _ in range(repeats):
            parser = PythonParser(
                pypi_client=FakePyPIClient()
            )

            with contextlib.redirect_stdout(io.StringIO()):
                start = time.perf_counter()
                nodes = parser.parse(str(path))
                elapsed = time.perf_counter() - start

            times.append(elapsed)
            node_counts.append(len(nodes))

        print(
            f"{count:>4} packages | "
            f"avg={statistics.mean(times):.6f}s | "
            f"min={min(times):.6f}s | "
            f"max={max(times):.6f}s | "
            f"nodes={node_counts}"
        )


print("=== BOMerang Python Parser Benchmark ===")

for count in [10, 50, 100, 500]:
    benchmark(count)
