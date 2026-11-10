"""Run the real shell pipeline with local acquisition/scanner substitutes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def write(path, content):
    path.write_text(content, encoding="utf-8", newline="\n")


@pytest.fixture
def pipeline(tmp_path):
    bash = (Path("C:/Program Files/Git/bin/bash.exe") if os.name == "nt"
            else Path(shutil.which("bash") or "/nonexistent"))
    if not bash.is_file():
        pytest.skip("Bash is required")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("run-scan.sh", "generate-sboms.sh", "scan-configurations.sh",
                 "helm-render-helpers.sh", "helm-dependency-helpers.sh"):
        shutil.copyfile(SCRIPTS / name, scripts / name)
    for name in ("prepare-inputs.sh", "scan-sboms.sh", "report.sh",
                 "report-to-portal.sh", "assemble-results.sh"):
        write(scripts / name, '#!/bin/bash\ntouch "ran-$(basename "$0")"\n')
    for name in ("normalize-trivy-config.sh", "normalize-dockle-config.sh"):
        write(scripts / name, r'''#!/bin/bash
if [ "$FAILED_STAGE" = normalize ]; then exit 27; fi
printf '[{"fingerprint":"%s/%s"}]\n' "$3" "$(basename "$0")" > "$2"
''')
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    write(inputs / "images.yml", json.dumps({"images": [f"registry.test/image:{i}" for i in range(12)]}))
    write(inputs / "service.yml", "service: test\n")
    # An unrelated existing archive and caller TMPDIR contents must survive.
    (inputs / ".cats-images").mkdir()
    write(inputs / ".cats-images" / "user-input.tar", "preserve me")
    scratch = tmp_path / "temporary files"
    scratch.mkdir()
    write(scratch / "caller-owned", "preserve me")
    write(tmp_path / "fake.py", FAKES)
    write(tmp_path / "wrapper.sh", WRAPPER)
    return bash, tmp_path


def run_pipeline(pipeline, failure="none", mode="scan", strict=False, source=False):
    bash, root = pipeline
    if failure != "none":
        write(root / "inputs/images.yml", json.dumps({"images": [f"registry.test/image:{i}" for i in range(3)]}))
    env = os.environ.copy()
    env.update(TEST_PYTHON=sys.executable, TEST_HELPER=str(root / "fake.py"), TEST_ROOT=str(root),
               FAILED_STAGE=failure, CATS_JOB_MODE=mode, CATS_IMAGE_SOURCE="daemonless",
               TRIVY_CONFIG_SCAN_ENABLED=str(source).lower(), HELM_SCAN_ENABLED="false",
               TRIVY_IMAGE_CONFIG_SCAN_ENABLED="true", DOCKLE_IMAGE_CONFIG_SCAN_ENABLED="true",
               TRIVY_CONFIG_STRICT=str(strict).lower())
    return subprocess.run([str(bash), "wrapper.sh"], cwd=root, env=env,
                          capture_output=True, text=True, timeout=120)


def assert_released(root):
    output = root / "output"
    assert not list(output.glob(".cats-images/image.*"))
    assert not list(output.glob(".cats-image-configuration.*"))
    assert not list((root / "temporary files").glob("cats-acquire.*"))
    assert (root / "temporary files/caller-owned").read_text() == "preserve me"
    assert (output / ".cats-images/user-input.tar").read_text() == "preserve me"


def test_many_images_release_archives_and_merge_configuration_evidence(pipeline):
    result = run_pipeline(pipeline, source=True)
    _, root = pipeline
    assert result.returncode == 0, result.stdout + result.stderr
    assert_released(root)
    output = root / "output"
    events = [json.loads(line) for line in (output / "calls.jsonl").read_text().splitlines()]
    acquisitions = [event for event in events if event["action"] == "acquire"]
    assert len(acquisitions) == 12
    assert all(event["existing_archives"] == 0 for event in acquisitions)
    assert len([event for event in events if event["action"] == "convert"]) == 12
    assert max(event.get("live_archives", 0) for event in events) == 2
    for action in ("inventory", "image-configuration", "image-hardening"):
        assert len([event for event in events if event["action"] == action]) == 12
    assert len([event for event in events if event["action"] == "configuration"]) == 1
    status = json.loads((output / "configuration-scan-status.json").read_text())
    assert status["complete"]
    assert status["source"] == {"requested": 13, "succeeded": 13}
    assert status["dockle"] == {"requested": 12, "succeeded": 12}
    assert len(json.loads((output / "portal-policy-findings.json").read_text())) == 25
    assert len(list((output / "trivy-results/raw").glob("*.json"))) == 25
    assert len(list((output / "sboms").glob("*.digest"))) == 12


@pytest.mark.parametrize("failure", ["acquire", "inventory", "identity", "convert", "configuration", "normalize"])
def test_failed_consumers_release_archives(pipeline, failure):
    result = run_pipeline(pipeline, failure=failure)
    _, root = pipeline
    assert_released(root)
    output = root / "output"
    if failure == "normalize":
        assert result.returncode != 0
        assert json.loads((output / "scan-failure.json").read_text())["phase"] == "configuration_scan"
        assert not (output / "ran-report.sh").exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        status = json.loads((output / "configuration-scan-status.json").read_text())
        assert not status["complete"]
        assert status["failures"] == 3


def test_strict_image_failure_keeps_configuration_phase_attribution(pipeline):
    result = run_pipeline(pipeline, failure="configuration", strict=True)
    _, root = pipeline
    assert result.returncode != 0
    assert_released(root)
    failure = json.loads((root / "output/scan-failure.json").read_text())
    assert failure["phase"] == "configuration_scan"
    assert failure["exit_code"] == 1
    assert not (root / "output/ran-report.sh").exists()


def test_sbom_only_does_not_materialize_configuration_archive(pipeline):
    result = run_pipeline(pipeline, mode="sbom")
    _, root = pipeline
    assert result.returncode == 0, result.stdout + result.stderr
    assert_released(root)
    events = [json.loads(line) for line in (root / "output/calls.jsonl").read_text().splitlines()]
    assert len([event for event in events if event["action"] == "inventory"]) == 12
    assert not any(event["action"] in {"convert", "image-configuration", "image-hardening"} for event in events)
    assert max(event.get("live_archives", 0) for event in events) == 1


def test_term_during_inventory_releases_owned_work(pipeline):
    result = run_pipeline(pipeline, failure="cancel")
    _, root = pipeline
    assert result.returncode == 143, result.stdout + result.stderr
    assert_released(root)
    failure = json.loads((root / "output/scan-failure.json").read_text())
    assert failure["phase"] == "generate_sboms"
    assert failure["exit_code"] == 143


def test_unwritable_configuration_evidence_is_fatal_and_releases_image(pipeline):
    result = run_pipeline(pipeline, failure="fragment")
    _, root = pipeline
    assert result.returncode == 1, result.stdout + result.stderr
    assert_released(root)
    assert json.loads((root / "output/scan-failure.json").read_text())["phase"] == "generate_sboms"
    assert not (root / "output/ran-report.sh").exists()


def test_previously_and_later_skipped_images_keep_configuration_counts(pipeline):
    _, root = pipeline
    write(root / "inputs/images.yml", json.dumps({"images": [f"registry.test/image:{i}" for i in range(3)]}))
    write(root / "inputs/skipped_images.txt", "registry.test/image:0\n")
    write(root / "scripts/scan-sboms.sh", "#!/bin/bash\necho registry.test/image:1 >> skipped_images.txt\n")
    result = run_pipeline(pipeline)
    assert result.returncode == 0, result.stdout + result.stderr
    assert_released(root)
    output = root / "output"
    status = json.loads((output / "configuration-scan-status.json").read_text())
    assert status["source"] == {"requested": 3, "succeeded": 1}
    assert status["dockle"] == {"requested": 3, "succeeded": 1}
    assert status["failures"] == 2
    assert not status["complete"]
    assert len(json.loads((output / "portal-policy-findings.json").read_text())) == 2
    assert len(list((output / "trivy-results/raw").glob("*.json"))) == 2


WRAPPER = r'''#!/bin/bash
export PATH="/usr/bin:/bin:$PATH"
export TEST_POSIX_ROOT="$PWD"
export TMPDIR="$PWD/temporary files" DOCKER_CONFIG="$PWD/auth"
mkdir -p "$DOCKER_CONFIG"
printf '{}' > "$DOCKER_CONFIG/config.json"
jq() { "$TEST_PYTHON" "$TEST_HELPER" jq "$@"; }
yq() { "$TEST_PYTHON" "$TEST_HELPER" yq "$@"; }
skopeo() { "$TEST_PYTHON" "$TEST_HELPER" skopeo "$@"; }
mktemp() {
  if [ "$FAILED_STAGE" = fragment ] && [[ "${*: -1}" == *cats-image-configuration.*/image.XXXXXX ]]; then return 29; fi
  command mktemp "$@"
}
python3() {
  if [[ "$1" == */scanner-action.py ]] && [ "$2" = inventory ] && [ "$FAILED_STAGE" = cancel ]; then
    kill -TERM "$BASHPID"
    return 143
  fi
  "$TEST_PYTHON" "$TEST_HELPER" python "$@"
}
bwrap() { :; }
trivy() { :; }
dockle() { :; }
docker() { echo 'Unexpected Docker invocation' >&2; return 97; }
export -f jq yq skopeo python3 bwrap trivy dockle docker mktemp
exec bash scripts/run-scan.sh "$PWD/inputs" "$PWD/output"
'''


FAKES = r'''
import json, os, sys
from pathlib import Path

sys.stdout.reconfigure(newline='\n')
kind, *args = sys.argv[1:]
failed = os.environ['FAILED_STAGE']
def local_path(value):
    if os.name == 'nt' and value.startswith('/') and '/output/' in value:
        return Path(os.environ['TEST_ROOT']) / 'output' / value.split('/output/', 1)[1]
    return Path(value)
def emit(value):
    print(json.dumps(value))
def event(action, **values):
    values.update(action=action, live_archives=len(list(Path('.cats-images').glob('image.*/*.tar'))))
    with open('calls.jsonl', 'a') as handle:
        handle.write(json.dumps(values) + '\n')
def read(path):
    return json.loads(Path(path).read_text())

if kind == 'yq':
    images = read(args[-1])['images']
    if args[0] == '-e':
        sys.exit(0 if images else 1)
    if 'length' in args[-2]: print(len(images))
    else: emit(images)
elif kind == 'skopeo':
    assert args[:1] == ['--tmpdir'] and args[2] == 'copy'
    stage = Path(args[1]); assert stage.is_dir()
    (stage / 'partial-layer').write_bytes(b'layer staging')
    source, destination = args[-2:]
    action = 'acquire' if source.startswith('docker://') else 'convert'
    if action == 'acquire':
        existing = len(list(Path('.cats-images').glob('image.*/*.tar')))
        assert existing == 0, 'previous image archives remain'
        assert args[3] == '--preserve-digests' and args[4] == '--src-authfile'
        payload = source.removeprefix('docker://')
    else:
        assert len(args) == 5, 'conversion received acquisition credentials'
        payload = local_path(source.split(':', 1)[1]).read_text()
    local_path(destination.split(':', 1)[1]).write_text(payload)
    event(action, **({'existing_archives': existing} if action == 'acquire' else {}))
    if failed == action: sys.exit(23)
elif kind == 'python':
    script = Path(args[0]).name
    if script == 'scanner-action.py':
        action, source, output = args[1:4]
        assert Path(source).exists(), 'consumer archive already released'
        if action != 'configuration':
            payload = Path(source).read_text()
            assert payload.startswith('registry.test/image:')
        else:
            assert any('.cats-image-configuration.' in value for value in args[4:])
        event(action)
        Path(output).write_text('{"source":{"metadata":{}}}')
        if failed == action or (failed == 'configuration' and action == 'image-configuration'): sys.exit(24)
    elif script == 'sbom_identity.py':
        if failed == 'identity': sys.exit(25)
        emit({'image_digest': 'sha256:' + 'a' * 64})
    elif script == 'generate-sbom-formats.py':
        reports = [{'format': 'syft-json'} for _ in Path('sboms').glob('*.json')]
        Path('sboms/formats/manifest.json').write_text(json.dumps({'reports': reports}))
    elif script == 'extract-service-overview.py':
        pass
    else: raise AssertionError(args)
elif kind == 'jq':
    if args[0] == '-n':
        variables = {}; index = 1
        while args[index] in ('--arg', '--argjson'):
            flag, name, value = args[index:index+3]
            variables[name] = json.loads(value) if flag == '--argjson' else value
            index += 3
        if 'source_requested' in variables:
            emit({'enabled': variables['enabled'], 'complete': variables['complete'],
                  'source': {'requested': variables['source_requested'], 'succeeded': variables['source_succeeded']},
                  'dockle': {'requested': variables['dockle_requested'], 'succeeded': variables['dockle_succeeded']},
                  'helm': {'requested': variables['helm_requested'], 'succeeded': variables['helm_succeeded'], 'skipped': variables['helm_skipped']},
                  'failures': variables['failures']})
        else: emit(variables)
    elif args[0] == '-s':
        merged = read(args[-2]) + read(args[-1])
        emit(list({entry['fingerprint']: entry for entry in merged}.values()))
    elif args[0] == '-er' and args[1] == '--arg':
        json.load(sys.stdin)
        print(args[3].split(':')[0] + '@sha256:' + 'a' * 64)
    elif args[0] == '-er':
        state = read(args[-1])
        print('\t'.join(str(value) for value in [state['source']['requested'], state['source']['succeeded'], state['dockle']['requested'], state['dockle']['succeeded'], state['failures']]))
    elif args[0] == '-r':
        print('\n'.join(json.load(sys.stdin)))
    elif args[0] == 'length': print(len(read(args[-1])))
    elif args[0] == '-c': emit(['syft-json'])
    elif 'reports' in args[0]: print(len(read(args[-1])['reports']))
    else: raise AssertionError(args)
else: raise AssertionError(kind)
'''
