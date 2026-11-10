"""Ablate only the version-list cache in isolated copies of the final parser."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from benchmark_parser_comparison import ROOT, inputs, request, stage_variant, summary, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    options = parser.parse_args()
    out = options.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for label in ['cached', 'uncached']:
        stage_variant(out / 'variants' / label, ROOT)
    source = out / 'variants/uncached/python-parser/python_parser.py'
    text = source.read_text(encoding='utf-8')
    old = '    def _resolve_version(self, requirement):\n'
    assert text.count(old) == 1
    source.write_text(text.replace(old, old + '        self._available_versions_cache.clear()\n'), encoding='utf-8')
    cases = [case for case in inputs(out / 'inputs') if case['kind'] == 'shared']
    env = dict(os.environ, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None)
    workers = {label: subprocess.Popen([sys.executable, '-B', '-u', str(ROOT / 'ci/benchmark_parser_comparison.py'),
               '--worker', str(out / 'variants' / label)], cwd=out / 'variants' / label,
               env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               text=True, encoding='utf-8', bufsize=1) for label in ['cached', 'uncached']}
    result = {'python': sys.version, 'rounds': 15, 'warmups': 3,
              'intervention': 'Only the isolated uncached copy clears its version-list cache on each version resolution.',
              'version_delay_s': 0.002, 'metadata_delay_s': 0.0005, 'cases': {},
              'source_sha256': {label: hashlib.sha256((out / 'variants' / label / 'python-parser/python_parser.py').read_bytes()).hexdigest()
                                for label in workers}}
    try:
        for case in cases:
            samples = {label: [] for label in workers}
            for _ in range(3):
                for process in workers.values():
                    request(process, {'case': case})
            for number in range(15):
                labels = ['cached', 'uncached'] if number % 2 else ['uncached', 'cached']
                for label in labels:
                    samples[label].append(request(workers[label], {'case': case}))
            summaries = {label: summary(values) for label, values in samples.items()}
            assert summaries['cached']['semantic_sha256'] == summaries['uncached']['semantic_sha256']
            assert summaries['cached']['version_calls'] == [1]
            assert summaries['uncached']['version_calls'] == [180]
            assert summaries['cached']['metadata_calls'] == summaries['uncached']['metadata_calls'] == [62]
            result['cases'][case['name']] = {'samples': samples, 'summary': summaries, 'input': case}
            print(case['name'], json.dumps({label: round(values['median_ms'], 3) for label, values in summaries.items()}), flush=True)
        write(out / 'comparison.json', result)
    finally:
        for process in workers.values():
            if process.poll() is None:
                process.stdin.write('{"stop":true}\n')
                process.stdin.flush()
                process.wait(timeout=15)


if __name__ == '__main__':
    main()
