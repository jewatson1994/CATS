import importlib.util
import hashlib
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('configure_gitlab', Path(__file__).resolve().parents[2] / 'scripts/configure-discovery-gitlab.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

def test_configure_preserves_settings_and_checks_artifacts(tmp_path, monkeypatch):
    (tmp_path / 'deploy').mkdir()
    cache = tmp_path / 'cache'; cache.mkdir()
    (cache / 'chart.tgz').write_bytes(b'chart')
    profile = {'sources':['https://charts.example'], 'redirect_origins':[], 'token_origins':[], 'discovery_options':{'values_files':['values.yaml']}, 'artifacts':[{'kind':'helm','reference':'https://charts.example/chart','version':'1','path':'chart.tgz','sha256':hashlib.sha256(b'chart').hexdigest()}]}
    (tmp_path / 'deploy/discovery-gitlab-public.json').write_text(json.dumps(profile))
    env = tmp_path / '.env'; env.write_text('UNCHANGED=keep\nCATS_DISCOVERY_HELM_SOURCES=\'["https://existing.example"]\'\n')
    monkeypatch.setattr(setup,'ROOT',tmp_path)
    monkeypatch.setattr('sys.argv',['setup','--apply','--artifact-cache',str(cache)])
    setup.main()
    assert 'UNCHANGED=keep' in env.read_text()
    assert 'https://existing.example' in env.read_text()
    assert 'https://charts.example' in env.read_text()
    assert (tmp_path / 'deploy/discovery-mirror-local/chart.tgz').read_bytes() == b'chart'
    previous = env.read_bytes()
    (cache / 'chart.tgz').write_bytes(b'tampered')
    with pytest.raises(ValueError, match='verification failed'): setup.main()
    assert env.read_bytes() == previous
