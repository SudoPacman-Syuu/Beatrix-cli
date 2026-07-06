"""
Docker sandbox runtime for GHOST v2.

Runs shell/python/external-binary execution inside a single, disposable
container per investigation, so attacker-influenced commands never touch the
host. Pure-Python scanners still run in-process (see ``tools/scanner_tool``);
only ``shell`` / ``python_exec`` (and, later, ``run_external_tool``) route here.

The ``docker`` SDK is synchronous, so every call is pushed to a thread with
``asyncio.to_thread`` to keep the agent's event loop responsive. Command
timeouts are enforced with coreutils ``timeout`` *inside* the container (exit
124), which is more reliable than trying to kill a detached exec from outside.

Design notes / current scope (M2 first cut):
* One ``sleep infinity`` container per run, created lazily and torn down on
  ``aclose()``; run as a non-root user with a read-only-ish work dir volume.
* Image is configurable (``ai.sandbox_image``); defaults to a lean
  ``python:3.11-slim`` so the driver works before the full ``ghost-sandbox``
  image (Beatrix + external binaries + Playwright) is built.
* Egress policy is configurable via ``ai.sandbox_network`` (``open`` | ``none``):
  ``none`` starts the container fully network-isolated (``network_disabled``),
  so in-container shells and external binaries cannot reach anything —
  pure-Python in-process scanners still hit the target since they don't run in
  the container. Host-scoped allowlisting (only the target hosts) needs a forced
  egress proxy and is tracked separately; ``open`` (the default) keeps normal
  outbound so tools can reach the target.
"""

from __future__ import annotations

import asyncio
import io
import os
import tarfile
import tempfile
import uuid
from typing import Optional

from .base import ExecResult

DEFAULT_IMAGE = "python:3.11-slim"
WORKDIR = "/work"


class DockerRuntime:
    """Execute tools inside a per-run Docker container."""

    name = "docker"
    allows_exec = True  # the whole point of the sandbox is to allow exec safely

    def __init__(self, cfg=None, *, image: Optional[str] = None, mem_limit: str = "1g",
                 cpus: float = 2.0, network: Optional[str] = None):
        import docker  # dispatch only builds this when the daemon is reachable

        self._docker = docker
        self._client = docker.from_env()
        self.image = image or getattr(cfg, "sandbox_image", None) or DEFAULT_IMAGE
        self.mem_limit = mem_limit
        self.cpus = cpus
        # Egress policy: "open" (default) or "none" (network_disabled container).
        self.network = (network or getattr(cfg, "sandbox_network", None) or "open").lower()
        self._container = None
        self._lock = asyncio.Lock()

        # Host-side run dir bind-mounted at WORKDIR: artifacts land on the host,
        # and file I/O works reliably (unlike a tmpfs mount, whose extraction is
        # masked). The container runs as this host uid/gid (non-root) so it owns
        # the mounted files and host<->container reads/writes just work.
        self.host_workdir = tempfile.mkdtemp(prefix="ghost2-sandbox-")
        self._run_uid = os.getuid()
        self._run_gid = os.getgid()

        # Fail fast (so dispatch can fall back to host) if the image can't be
        # obtained. Cheap when the image is already local.
        self._ensure_image()

    # ── image / container lifecycle ─────────────────────────────────────
    def _ensure_image(self) -> None:
        try:
            self._client.images.get(self.image)
        except self._docker.errors.ImageNotFound:
            self._client.images.pull(self.image)

    async def _container_obj(self):
        """Lazily create the run container; reused for every exec."""
        if self._container is not None:
            return self._container
        async with self._lock:
            if self._container is not None:
                return self._container
            self._container = await asyncio.to_thread(
                self._client.containers.run,
                self.image,
                command=["sleep", "infinity"],
                name=f"ghost2-{uuid.uuid4().hex[:12]}",
                detach=True,
                working_dir=WORKDIR,
                user=f"{self._run_uid}:{self._run_gid}",
                mem_limit=self.mem_limit,
                nano_cpus=int(self.cpus * 1e9),
                pids_limit=256,
                # Egress policy from ai.sandbox_network: "none" isolates the
                # container's network entirely; "open" keeps normal outbound.
                network_disabled=(self.network == "none"),
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                volumes={self.host_workdir: {"bind": WORKDIR, "mode": "rw"}},
            )
            return self._container

    async def aclose(self) -> None:
        """Stop and remove the run container. Best-effort."""
        c = self._container
        self._container = None
        if c is not None:
            try:
                await asyncio.to_thread(c.remove, force=True)
            except Exception:
                pass
        try:
            import shutil

            shutil.rmtree(self.host_workdir, ignore_errors=True)
        except Exception:
            pass

    # ── Runtime protocol ────────────────────────────────────────────────
    async def exec(self, command: str, *, timeout: int = 60, cwd: Optional[str] = None) -> ExecResult:
        container = await self._container_obj()
        # coreutils `timeout` bounds the command; exit 124 => timed out.
        wrapped = f"timeout {int(timeout)} /bin/sh -c {_shquote(command)}"
        res = await asyncio.to_thread(
            container.exec_run, ["/bin/sh", "-c", wrapped],
            workdir=cwd or WORKDIR, demux=True,
        )
        return _to_result(res)

    async def python(self, code: str, *, timeout: int = 60) -> ExecResult:
        # Snippet lives in the run's tmpfs, which is discarded on teardown — no
        # need to clean it up individually.
        rel = f"_snippet_{uuid.uuid4().hex[:8]}.py"
        await self.write_file(rel, code)
        return await self.exec(f"python {WORKDIR}/{rel}", timeout=timeout)

    def _host_path(self, path: str) -> Optional[str]:
        """Map a container path under WORKDIR to its host bind-mount path, or
        None if it lives outside the mounted run dir."""
        if not path.startswith("/"):
            return os.path.join(self.host_workdir, path)
        if path == WORKDIR or path.startswith(WORKDIR + "/"):
            rel = os.path.relpath(path, WORKDIR)
            return os.path.join(self.host_workdir, rel)
        return None

    async def write_file(self, path: str, content: str) -> None:
        host = self._host_path(path)
        if host is not None:  # common case: write straight to the bind mount
            await self._container_obj()  # ensure the mount exists
            os.makedirs(os.path.dirname(host) or self.host_workdir, exist_ok=True)
            await asyncio.to_thread(_write_text, host, content)
            return
        # Absolute path outside the run dir: stream a tar into the container.
        container = await self._container_obj()
        stream = _make_tar(_arcname(path), content.encode())
        await asyncio.to_thread(container.put_archive, "/", stream)

    async def read_file(self, path: str) -> str:
        host = self._host_path(path)
        if host is not None:
            await self._container_obj()
            return await asyncio.to_thread(_read_text, host)
        container = await self._container_obj()
        bits, _ = await asyncio.to_thread(container.get_archive, path)
        buf = io.BytesIO(b"".join(bits))
        with tarfile.open(fileobj=buf) as tar:
            member = tar.getmembers()[0]
            f = tar.extractfile(member)
            return f.read().decode(errors="replace") if f else ""


# ── helpers ─────────────────────────────────────────────────────────────
def _shquote(s: str) -> str:
    """Single-quote a string for /bin/sh."""
    return "'" + s.replace("'", "'\\''") + "'"


def _write_text(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def _read_text(path: str) -> str:
    with open(path, "r", errors="replace") as f:
        return f.read()


def _arcname(path: str) -> str:
    """Tar member name: relative to WORKDIR as-is, absolute stripped of its
    leading slash (extracted at ``/``). Docker recreates intermediate dirs."""
    return path[1:] if path.startswith("/") else path


def _make_tar(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _to_result(res) -> ExecResult:
    """Convert docker exec_run(demux=True) output to an ExecResult."""
    exit_code = res.exit_code if res.exit_code is not None else -1
    out_b, err_b = res.output if isinstance(res.output, tuple) else (res.output, None)
    stdout = out_b.decode(errors="replace") if out_b else ""
    stderr = err_b.decode(errors="replace") if err_b else ""
    return ExecResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=(exit_code == 124),
    )


__all__ = ["DockerRuntime", "DEFAULT_IMAGE"]
