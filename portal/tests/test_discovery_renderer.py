from pathlib import Path

import pytest

from app import discovery_renderer as renderer


@pytest.fixture(autouse=True)
def stub_packaged_intelligence_startup():
    # Renderer tests do not boot the application or require its database.
    pass


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(renderer, "PLATFORM", "linux")
    monkeypatch.setattr(renderer, "_effective_uid", lambda: 10003)
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda self: True if str(self).replace("\\", "/") in {
        "/usr/bin/bwrap", "/usr/local/bin/helm", "/usr/local/bin/kubectl",
        "/usr/local/bin/docker-compose"} else original(self))


def test_renderer_mounts_only_source_and_tool(linux, tmp_path):
    command = renderer.sandbox_command("helm", ["template", "test", str(tmp_path)], tmp_path)
    assert "--unshare-all" in command
    assert "--clearenv" in command
    assert "--unshare-user" in command
    assert command.count("--ro-bind") == 2
    assert "/app" not in command
    assert command[-4:] == ["/tool", "template", "test", "/source"]
    assert "HELM_PLUGINS" in command


def test_root_is_rejected(linux, monkeypatch, tmp_path):
    monkeypatch.setattr(renderer, "_effective_uid", lambda: 0)
    with pytest.raises(renderer.RendererError, match="non-root"):
        renderer.sandbox_command("helm", ["template"], tmp_path)


def test_missing_sandbox_fails_closed(linux, monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    with pytest.raises(renderer.RendererError, match="unavailable"):
        renderer.sandbox_command("helm", ["template"], tmp_path)


@pytest.mark.parametrize("tool,args", [
    ("helm", ["install"]), ("compose", ["up"]),
    ("kustomize", [".", "--enable-exec"]),
    ("helm", ["template", ".", "--post-renderer=/source/evil"]),
])
def test_non_render_commands_and_plugins_rejected(linux, tmp_path, tool, args):
    with pytest.raises(renderer.RendererError):
        renderer.sandbox_command(tool, args, tmp_path)


def test_kustomize_uses_bundled_kubectl(linux, tmp_path):
    command = renderer.sandbox_command("kustomize", ["."], tmp_path)
    assert command[-3:] == ["/tool", "kustomize", "."]


def test_non_linux_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(renderer, "PLATFORM", "win32")
    with pytest.raises(renderer.RendererError):
        renderer.sandbox_command("helm", ["template"], tmp_path)


def test_child_filter_architecture_and_namespace_denials(monkeypatch):
    import struct
    monkeypatch.setattr(renderer.platform, 'machine', lambda: 'x86_64')
    with renderer.child_seccomp() as policy:
        instructions = list(struct.iter_unpack('HBBI', policy.read()))
    def evaluate(syscall, flags=0, arch=0xC000003E):
        data = {0: syscall, 4: arch, 16: flags}
        pc = accumulator = 0
        while pc < len(instructions):
            code, yes, no, value = instructions[pc]
            if code == 0x20:
                accumulator = data[value]
            elif code == 0x15:
                pc += yes if accumulator == value else no
            elif code == 0x45:
                pc += yes if accumulator & value else no
            elif code == 0x06:
                return value
            pc += 1
        raise AssertionError('filter did not return')
    assert evaluate(0) == 0x7FFF0000
    assert evaluate(56, 0x100) == 0x7FFF0000  # ordinary thread clone
    for syscall in (272, 308, 165, 166, 155):
        assert evaluate(syscall) == 0x00050001
    for namespace in (0x20000, 0x02000000, 0x04000000, 0x08000000,
                      0x10000000, 0x20000000, 0x40000000):
        assert evaluate(56, namespace) == 0x00050001
    assert evaluate(435) == 0x00050026
    assert evaluate(0, arch=0) == 0x80000000
    assert evaluate(0x40000000) == 0x80000000


def test_unknown_filter_architecture_fails_closed(monkeypatch):
    monkeypatch.setattr(renderer.platform, 'machine', lambda: 'unknown')
    with pytest.raises(renderer.RendererError, match='architecture'):
        renderer.child_seccomp()


def test_missing_value_paths_excludes_error_values():
    message = "Please set `global.psql.host` and `global.psql.password.secret`. nil pointer at .Values.redis.host; password=DO_NOT_PERSIST https://private.invalid/token"
    assert renderer.missing_value_paths(message) == ['global.psql.host', 'global.psql.password.secret', 'redis.host']


def test_gitlab_required_email_message_exposes_key_only():
    message = 'You must provide an email to associate with your TLS certificates. Please set certmanager-issuer.email'
    assert renderer.missing_value_paths(message) == ['certmanager-issuer.email']
