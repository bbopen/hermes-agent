#!/usr/bin/env python3
"""Two-process A2A smoke harness for a primary Hermes and a Mac worker.

This intentionally uses separate processes and HERMES_HOME directories so the
test exercises the same state-isolation boundary as two physical hosts.  The
worker uses the real A2A HTTP adapter; the primary uses the real ``a2a_call``
client.  Only the worker writes the simulated Mac-local proof artifact.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _run_worker(port: int, worker_home: Path) -> None:
    from gateway.config import PlatformConfig
    from plugins.platforms.a2a.adapter import A2AAdapter

    adapter = A2AAdapter(PlatformConfig(enabled=True))
    turns: dict[str, int] = {}

    async def execute_mac_local_task(event):
        context_id = event.source.chat_id
        turns[context_id] = turns.get(context_id, 0) + 1
        proof = worker_home / "mac-local-proof.txt"
        proof.write_text(
            f"context={context_id}\nturn={turns[context_id]}\n",
            encoding="utf-8",
        )
        await adapter.send(
            context_id,
            "worker accepted bounded task",
            metadata={"expect_edits": True},
        )
        await adapter.send(
            context_id,
            f"APPLE_WORKER_OK context={context_id} turn={turns[context_id]}",
            metadata={"notify": True},
        )

    adapter.handle_message = execute_mac_local_task  # type: ignore[method-assign]
    adapter._message_handler = object()  # The gateway normally installs this.
    if not await adapter.connect():
        raise RuntimeError("worker A2A adapter failed to start")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(json.dumps({"ready": True, "port": port}), flush=True)
    await stop.wait()
    await adapter.disconnect()


def _worker_main(args: argparse.Namespace) -> int:
    worker_home = Path(args.worker_home).resolve()
    worker_home.mkdir(parents=True, exist_ok=True)
    asyncio.run(_run_worker(args.port, worker_home))
    return 0


def _context_from_reply(reply: str) -> str:
    marker = " · context "
    if marker not in reply:
        raise AssertionError(f"missing context in reply: {reply!r}")
    return reply.split(marker, 1)[1].split(" ·", 1)[0].split("]", 1)[0]


def _primary_main() -> int:
    from plugins.platforms.a2a import tools

    token = "harness-only-token"
    with tempfile.TemporaryDirectory(prefix="hermes-a2a-primary-") as primary_dir, tempfile.TemporaryDirectory(
        prefix="hermes-a2a-worker-"
    ) as worker_dir:
        port = _free_port()
        env = os.environ.copy()
        env.update(
            {
                "HERMES_HOME": worker_dir,
                "A2A_BEARER_TOKEN": token,
                "A2A_HOST": "127.0.0.1",
                "A2A_PORT": str(port),
                "A2A_AGENT_NAME": "apple-worker-harness",
            }
        )
        proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                "--port",
                str(port),
                "--worker-home",
                worker_dir,
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            ready = ""
            while time.monotonic() < deadline:
                ready = proc.stdout.readline() if proc.stdout else ""
                if ready:
                    break
                if proc.poll() is not None:
                    break
            if not ready:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"worker failed to become ready: {stderr}")
            assert json.loads(ready)["ready"] is True

            os.environ["HERMES_HOME"] = primary_dir
            tools._resolve_peer = lambda _agent: {  # type: ignore[assignment]
                "url": f"http://127.0.0.1:{port}",
                "auth": {"type": "bearer", "token": token},
                "timeout": 10,
            }

            first = tools.a2a_call({"agent": "apple-worker", "message": "write bounded proof"})
            context_id = _context_from_reply(first)
            second = tools.a2a_call(
                {
                    "agent": "apple-worker",
                    "message": "continue in the same worker session",
                    "context_id": context_id,
                }
            )

            assert "APPLE_WORKER_OK" in first and "turn=1" in first
            assert f"context={context_id}" in second and "turn=2" in second
            proof = Path(worker_dir, "mac-local-proof.txt")
            assert proof.exists() and "turn=2" in proof.read_text(encoding="utf-8")
            assert not Path(primary_dir, "mac-local-proof.txt").exists()
            assert Path(primary_dir, "a2a_audit.jsonl").exists()
            assert Path(worker_dir, "a2a_audit.jsonl").exists()

            print(
                json.dumps(
                    {
                        "ok": True,
                        "context_id": context_id,
                        "multi_turn": True,
                        "final_reply_capture": True,
                        "worker_local_side_effect": str(proof),
                        "separate_hermes_homes": True,
                    },
                    indent=2,
                )
            )
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--port", type=int)
    parser.add_argument("--worker-home")
    args = parser.parse_args()
    if args.worker:
        if args.port is None or not args.worker_home:
            parser.error("--worker requires --port and --worker-home")
        return _worker_main(args)
    return _primary_main()


if __name__ == "__main__":
    raise SystemExit(main())
