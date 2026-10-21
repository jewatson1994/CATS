#!/usr/bin/env python3
"""Bounded native renderer benchmark; run inside the hardened Discovery image."""
import concurrent.futures
import json
from pathlib import Path
import statistics
import tempfile
import time

from app.discovery_renderer import isolated_runner


def main():
    with tempfile.TemporaryDirectory(prefix='discovery-benchmark-') as directory:
        root = Path(directory)
        helm = root / 'helm'
        (helm / 'templates').mkdir(parents=True)
        (helm / 'Chart.yaml').write_text('apiVersion: v2\nname: benchmark\nversion: 1.0.0\n')
        resources = '\n---\n'.join('apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: benchmark-%d\ndata:\n  setting: synthetic\n' % i for i in range(100))
        (helm / 'templates/resources.yaml').write_text(resources)
        kustomize = root / 'kustomize'
        kustomize.mkdir()
        (kustomize / 'resources.yaml').write_text(resources)
        (kustomize / 'kustomization.yaml').write_text('resources:\n  - resources.yaml\n')
        compose = root / 'compose'
        compose.mkdir()
        (compose / 'compose.yaml').write_text('services:\n' + ''.join('  service%d:\n    image: example.invalid/app:1\n    environment:\n      SETTING: synthetic\n' % i for i in range(100)))
        cases = [('helm', ['template', 'benchmark', str(helm)], helm),
                 ('kustomize', ['build', str(kustomize)], kustomize),
                 ('compose', ['-f', str(compose / 'compose.yaml'), 'config'], compose)]
        def run(case):
            tool, args, cwd = case
            start = time.perf_counter()
            result = isolated_runner(tool, args, cwd, timeout=30, max_output=2 * 1024 * 1024)
            return {'tool': tool, 'seconds': round(time.perf_counter() - start, 4), 'output_bytes': len(result['stdout'].encode())}
        report = {'objects_per_source': 100, 'jobs': 12, 'results': []}
        for concurrency in (1, 4):
            start = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                rows = list(pool.map(run, cases * 4))
            report['results'].append({'concurrency': concurrency, 'wall_seconds': round(time.perf_counter() - start, 4), 'median_job_seconds': round(statistics.median(row['seconds'] for row in rows), 4), 'max_job_seconds': max(row['seconds'] for row in rows), 'jobs': rows})
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
