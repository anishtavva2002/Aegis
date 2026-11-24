import tempfile
from pathlib import Path
import docker
from docker.errors import DockerException, ImageNotFound

class DockerRunner:
    """Runs code in a bounded container. Requires a trusted local Docker daemon."""

    def __init__(self, image="python:3.12-slim"):
        self.image = image
        self.client = docker.from_env()

    def run(self, source: str, policy: dict):
        try:
            self.client.ping()
        except DockerException as exc:
            raise RuntimeError(f"Docker daemon is unavailable: {exc}") from exc
        try:
            self.client.images.get(self.image)
        except ImageNotFound:
            self.client.images.pull(self.image)

        with tempfile.TemporaryDirectory(prefix="aegis-job-") as tmp:
            work = Path(tmp)
            script = work / "job.py"
            script.write_text(source, encoding="utf-8")
            try:
                container = self.client.containers.run(
                    self.image,
                    command=["python", "-I", "/workspace/job.py"],
                    detach=True,
                    network_disabled=True,
                    read_only=True,
                    mem_limit=policy["memory_limit"],
                    nano_cpus=int(policy["nano_cpus"]),
                    pids_limit=int(policy["pids_limit"]),
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    user="65534:65534",
                    tmpfs={"/tmp": "rw,noexec,nosuid,size=16m"},
                    volumes={str(work): {"bind": "/workspace", "mode": "ro"}},
                    working_dir="/workspace",
                    stdin_open=False,
                    tty=False,
                    labels={"org.aegis.managed": "true"}
                )
            except DockerException as exc:
                raise RuntimeError(f"Could not create isolated container: {exc}") from exc
            try:
                result = container.wait(timeout=int(policy["max_timeout_seconds"]))
                logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
                status = result.get("StatusCode", 1)
                return {"status": "completed" if status == 0 else "failed",
                        "exit_code": status, "output": logs[-12000:],
                        "container_id": container.short_id}
            except Exception as exc:
                try:
                    container.kill()
                except Exception:
                    pass
                raise RuntimeError(f"Execution timed out or failed: {exc}") from exc
            finally:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
