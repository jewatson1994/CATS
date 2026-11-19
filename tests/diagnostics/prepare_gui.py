"""Prepare a disposable current-source GUI acceptance stack; no existing data mounted."""
import json
from pathlib import Path

source = Path(__file__).resolve().parents[2]
run = source / '.test-temp' / 'diagnostics-gui-20261116'
run.mkdir(parents=True, exist_ok=False)
url = 'postgresql+psycopg://postgres:diagnostics-disposable-only@db/diagnostics'
compose = {
    'name': 'cats-diagnostics-gui-20261116',
    'networks': {
        'default': {'internal': True, 'ipam': {'config': [{'subnet': '10.245.16.0/24'}]}},
        'ingress': {'ipam': {'config': [{'subnet': '10.245.19.0/24'}]}},
    },
    'services': {
        'db': {
            'image': 'postgres:16-alpine',
            'environment': {'POSTGRES_PASSWORD': 'diagnostics-disposable-only', 'POSTGRES_DB': 'diagnostics'},
            'healthcheck': {'test': ['CMD-SHELL', 'pg_isready -U postgres -d diagnostics'], 'interval': '2s', 'timeout': '2s', 'retries': 30},
        },
        'portal': {
            'image': 'cats:remaining-20261107',
            'entrypoint': ['/opt/cats-venv/bin/python', '-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000'],
            'working_dir': '/source/portal',
            'volumes': [str(source / 'portal') + ':/source/portal:ro', str(source / 'tests' / 'diagnostics') + ':/acceptance:ro', str(run) + ':/evidence'],
            'ports': ['127.0.0.1:18089:8000'],
            'networks': ['default', 'ingress'],
            'environment': {
                'DATABASE_URL': url, 'INTELLIGENCE_DATABASE_URL': url,
                'PYTHONPATH': '/source/portal', 'PYTHONDONTWRITEBYTECODE': '1',
                'CATS_BOOTSTRAP_USERNAME': 'diagnostics-admin',
                'CATS_BOOTSTRAP_PASSWORD': 'Diagnostics-Acceptance-Only-2026',
                'SESSION_COOKIE_SECURE': 'false',
                'PIPELINE_API_TOKEN': 'diagnostics-fixture-pipeline-only',
                'CATS_DEPLOYMENT_VALIDATION_ENABLED': 'false',
            },
            'depends_on': {'db': {'condition': 'service_healthy'}},
        },
    },
}
(run / 'compose.json').write_text(json.dumps(compose, indent=2))
print(run / 'compose.json')
