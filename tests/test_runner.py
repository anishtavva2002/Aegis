from unittest.mock import MagicMock

import pytest

docker = pytest.importorskip("docker")

from aegis.policy import PolicyEngine  # noqa: E402
from aegis.runner import DockerRunner  # noqa: E402


def fake_client(exit_code=0):
    client = MagicMock()
    container = MagicMock()
    container.wait.return_value = {"StatusCode": exit_code}
    container.logs.return_value = b"hello\n"
    container.short_id = "abc123"
    client.containers.run.return_value = container
    return client, container


def run(policy_overrides=None, exit_code=0):
    client, container = fake_client(exit_code)
    policy = dict(PolicyEngine().policy)
    policy.update(policy_overrides or {})
    result = DockerRunner(client=client).run('print("hi")', policy)
    return client, container, result


def test_container_is_locked_down():
    client, container, result = run()
    kwargs = client.containers.run.call_args.kwargs
    assert kwargs["network_disabled"] is True
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["user"] == "65534:65534"
    assert "runtime" not in kwargs
    assert result["status"] == "completed" and result["output"] == "hello\n"
    container.remove.assert_called_once_with(force=True)


def test_gvisor_runtime_is_passed_through():
    client, _, _ = run({"runtime": "runsc"})
    assert client.containers.run.call_args.kwargs["runtime"] == "runsc"


def test_nonzero_exit_is_failed():
    _, _, result = run(exit_code=3)
    assert result["status"] == "failed" and result["exit_code"] == 3


def test_timeout_kills_and_cleans_up():
    client, container = fake_client()
    container.wait.side_effect = TimeoutError("too slow")
    with pytest.raises(RuntimeError):
        DockerRunner(client=client).run("x=1", dict(PolicyEngine().policy))
    container.kill.assert_called_once()
    container.remove.assert_called_once_with(force=True)


def test_invalid_runtime_rejected(tmp_path):
    path = tmp_path / "p.json"
    path.write_text('{"runtime": "evil"}')
    with pytest.raises(ValueError):
        PolicyEngine(path)
