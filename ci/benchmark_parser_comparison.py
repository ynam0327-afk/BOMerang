"""Isolated, warmed, interleaved Python parser benchmark and cProfile runner.

No checkout files are replaced. Each output directory must be new.
"""
import argparse
import contextlib
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pstats
import cProfile
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def write(path, data):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def worker(stage):
    sys.path.insert(0, str(stage / 'python-parser'))
    from python_parser import PythonParser
    from packaging.requirements import Requirement
    class Client:
        def __init__(self, case):
            self.case = case
            self.version_calls = 0
            self.metadata_calls = 0
        def get_available_versions(self, name):
            self.version_calls += 1
            if self.case.get('version_delay', 0):
                time.sleep(self.case['version_delay'])
            return ['1.0.0', '1.5.0', '2.0.0']
        def get_dependencies(self, name, version, extras=None):
            self.metadata_calls += 1
            if self.case.get('metadata_delay', 0):
                time.sleep(self.case['metadata_delay'])
            if self.case['kind'] == 'recursive':
                index = 0 if name == 'parent' else int(name.split('-')[-1])
                if index < self.case['size']:
                    return [Requirement(f'child-{index + 1}==1.0.0')]
            if self.case['kind'] == 'shared' and name.startswith('parent-'):
                return [Requirement('shared>=1,<2'), Requirement('shared>=2,<3'), Requirement('shared>=1,<2')]
            return []
    log = (stage / 'timed-stderr.log').open('x', encoding='utf-8')
    for line in sys.stdin:
        command = json.loads(line)
        if command.get('stop'):
            break
        case = command['case']
        client = Client(case)
        parser = PythonParser(client)
        sink = log if case.get('sink') == 'file' else io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(sink):
            profile = cProfile.Profile() if command.get('profile') else None
            if profile:
                profile.enable()
            wall = time.perf_counter_ns()
            cpu = time.process_time_ns()
            nodes = parser.parse(case['path'])
            cpu = time.process_time_ns() - cpu
            wall = time.perf_counter_ns() - wall
            if profile:
                profile.disable()
        rows = [asdict(n) for n in nodes]
        identity = sorted((r['purl'], r['resolved_version'], sorted(r['dependencies']), r['depth'],
                           r['parse_status'], r['error_message'], r['is_circular']) for r in rows)
        semantic = {'nodes': rows, 'declarations': parser.declarations,
                    'declaration_packages': parser.declaration_packages, 'errors': parser.declaration_errors}
        result = {'wall_ms': wall / 1e6, 'cpu_ms': cpu / 1e6, 'nodes': len(nodes),
                  'version_calls': client.version_calls, 'metadata_calls': client.metadata_calls,
                  'graph_sha256': digest(identity), 'semantic_sha256': digest(semantic)}
        if profile:
            destination = Path(command['profile'])
            profile.dump_stats(str(destination.with_suffix('.prof')))
            with destination.with_suffix('.txt').open('x', encoding='utf-8') as stream:
                pstats.Stats(profile, stream=stream).strip_dirs().sort_stats('cumulative').print_stats(50)
            stats = pstats.Stats(profile)
            result['profile'] = [dict(file=str(Path(key[0]).name), line=key[1], function=key[2],
                                      primitive_calls=value[0], calls=value[1], own_s=value[2], cumulative_s=value[3])
                                 for key, value in stats.stats.items()]
        print(json.dumps(result), flush=True)
    log.close()


def stage_variant(destination, reference=None, head=False):
    destination.mkdir(parents=True)
    parser = destination / 'python-parser'
    parser.mkdir()
    for path in sorted((reference or ROOT).joinpath('python-parser').glob('*.py')):
        data = subprocess.check_output(['git', 'show', 'HEAD:python-parser/' + path.name], cwd=ROOT) if head else path.read_bytes()
        (parser / path.name).write_bytes(data)
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in parser.glob('*.py')}


def inputs(directory):
    directory.mkdir()
    cases = []
    def add(name, kind, size, text, filename='requirements.txt', **kw):
        folder = directory / name.replace('/', '-')
        folder.mkdir()
        path = folder / filename
        path.write_text(text, encoding='utf-8')
        cases.append(dict(name=name, kind=kind, size=size, path=str(path), sink='memory', **kw))
    for size in [10, 50, 100, 500]:
        add(f'requirements/{size}', 'requirements', size, ''.join(f'benchmark-pkg-{i}==1.0.0\n' for i in range(size)))
    for size in [1, 3, 5, 10]:
        add(f'recursive/{size}', 'recursive', size, 'parent==1.0.0\n')
    for poetry in [False, True]:
        for size in [10, 50, 100]:
            if poetry:
                text = '[tool.poetry]\nname="benchmark-project"\nversion="0.1.0"\n[tool.poetry.dependencies]\npython=">=3.10"\n'
                text += ''.join(f'benchmark-pkg-{i}="==1.0.0"\n' for i in range(size))
            else:
                text = '[project]\nname="benchmark-project"\nversion="0.1.0"\ndependencies=[' + ','.join(f'"benchmark-pkg-{i}==1.0.0"' for i in range(size)) + ']\n'
            add(f'{"poetry" if poetry else "pep621"}/{size}', 'toml', size, text, 'pyproject.toml')
    for delay in [0, 0.002]:
        add('shared/' + ('latency' if delay else 'cpu'), 'shared', 60,
            ''.join(f'parent-{i}==1.0.0\n' for i in range(60)), version_delay=delay, metadata_delay=0.0005 if delay else 0)
    case = dict(cases[3])
    case.update(name='requirements/500-file-stderr', sink='file')
    cases.append(case)
    return cases


def request(process, command):
    process.stdin.write(json.dumps(command) + '\n')
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError('Worker failed: ' + process.stderr.read())
    return json.loads(line)


def summary(samples):
    values = [s['wall_ms'] for s in samples]
    quartiles = statistics.quantiles(values, n=4, method='inclusive')
    return {'median_ms': statistics.median(values), 'mean_ms': statistics.mean(values),
            'min_ms': min(values), 'max_ms': max(values), 'iqr_ms': quartiles[2] - quartiles[0],
            'cpu_median_ms': statistics.median(s['cpu_ms'] for s in samples),
            'node_counts': sorted(set(s['nodes'] for s in samples)),
            'version_calls': sorted(set(s['version_calls'] for s in samples)),
            'metadata_calls': sorted(set(s['metadata_calls'] for s in samples)),
            'graph_sha256': sorted(set(s['graph_sha256'] for s in samples)),
            'semantic_sha256': sorted(set(s['semantic_sha256'] for s in samples))}


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--worker', type=Path)
    args.add_argument('--output', type=Path)
    args.add_argument('--reference', action='append', default=[], help='name=directory containing python-parser')
    args.add_argument('--rounds', type=int, default=15)
    args.add_argument('--warmups', type=int, default=3)
    options = args.parse_args()
    if options.worker:
        worker(options.worker)
        return
    out = options.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    variants = {'head': None, 'current': ROOT}
    variants.update(dict((key, Path(value).resolve()) for key, value in (v.split('=', 1) for v in options.reference)))
    hashes = {key: stage_variant(out / 'variants' / key, value, key == 'head') for key, value in variants.items()}
    cases = inputs(out / 'inputs')
    env = dict(os.environ, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None)
    workers = {key: subprocess.Popen([sys.executable, '-B', '-u', str(Path(__file__).resolve()), '--worker', str(out / 'variants' / key)],
               cwd=out / 'variants' / key, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1) for key in variants}
    result = {'python': sys.version, 'platform': platform.platform(), 'started_at': datetime.now(timezone.utc).isoformat(),
              'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'rounds': options.rounds, 'warmups': options.warmups, 'timing': 'parse only; client/parser construction, fingerprints and IPC excluded',
              'version_delay_s': 0.002, 'metadata_delay_s': 0.0005, 'hashes': hashes, 'cases': {}, 'profiles': {}}
    labels = list(workers)
    try:
        for case in cases:
            samples = {key: [] for key in labels}
            for _ in range(options.warmups):
                for key in labels:
                    request(workers[key], {'case': case})
            for round_number in range(options.rounds):
                order = labels[round_number % len(labels):] + labels[:round_number % len(labels)]
                if (round_number // len(labels)) % 2:
                    order.reverse()
                for key in order:
                    samples[key].append(request(workers[key], {'case': case}))
            result['cases'][case['name']] = {'input': case, 'samples': samples,
                                            'summary': {key: summary(values) for key, values in samples.items()}}
            print(case['name'], json.dumps({key: round(summary(values)['median_ms'], 3) for key, values in samples.items()}), flush=True)
        profiles = out / 'profiles'
        profiles.mkdir()
        for name in ['requirements/500', 'recursive/10', 'pep621/100', 'poetry/100', 'shared/cpu']:
            case = next(c for c in cases if c['name'] == name)
            result['profiles'][name] = {}
            for key in labels:
                result['profiles'][name][key] = request(workers[key], {'case': case, 'profile': str(profiles / (key + '-' + name.replace('/', '-')))})
        write(out / 'comparison.json', result)
    finally:
        for process in workers.values():
            if process.poll() is None:
                process.stdin.write('{"stop": true}\n')
                process.stdin.flush()
                process.wait(timeout=15)
    # Run unchanged original scripts, with identical file-backed stderr sinks.
    for script, label in [('benchmark_python_parser.py', 'requirements'), ('benchmark_recursive_parser.py', 'recursive'), ('benchmark_toml_parser.py', 'toml')]:
        for key in labels:
            with (out / ('original-' + label + '-' + key + '.txt')).open('x', encoding='utf-8') as stdout:
                with (out / ('original-' + label + '-' + key + '-stderr.log')).open('x', encoding='utf-8') as stderr:
                    subprocess.run([sys.executable, '-B', str(ROOT / script)], cwd=out / 'variants' / key, env=env, stdout=stdout, stderr=stderr, check=True)
    print('Saved comparison.json, profiles and unchanged benchmark outputs.', flush=True)


if __name__ == '__main__':
    main()
