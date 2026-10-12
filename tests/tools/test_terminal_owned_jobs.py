"""POSIX: terminal commands die with the Hermes process that started them.

The owners are real host processes using the real ``LocalEnvironment.execute``. One owner is SIGKILLed,
so no Python cleanup of ours runs; the other is the live-owner control.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

import psutil
import pytest

from tests.waiting import wait_until

pytestmark = pytest.mark.platforms("posix")

_OWNER = r'''
import json, os, sys, threading, time
from pathlib import Path
root, role = Path(sys.argv[1]), sys.argv[2]
from tools.environments.local import LocalEnvironment
ids = {}
env = LocalEnvironment(cwd=str(root), timeout=600)
fg = root / f"{role}.fg"
threading.Thread(target=env.execute, args=(f"sleep 120 & echo $! > {fg}; wait",), daemon=True).start()
wait_until = time.time() + 30
while not fg.exists() and time.time() < wait_until:
    time.sleep(0.05)
ids["foreground"] = [int(fg.read_text().strip())]
out = {}
for name, pids in ids.items():
    out[name] = [{"pid": pid, "created": __import__("psutil").Process(pid).create_time()} for pid in pids]
(root / (role + ".tmp")).write_text(json.dumps(out))
os.replace(root / (role + ".tmp"), root / (role + ".json"))
while True:
    time.sleep(1)
'''


def _alive(identity):
    """Zombie-aware: a killed non-child lingers as a zombie until its reaper collects it."""
    try:
        proc = psutil.Process(identity["pid"])
        return proc.create_time() == identity["created"] and proc.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _read(path):
    wait_until(path.exists, timeout=60, what=f"owner receipt {path.name}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _run_owners(tmp_path, roles):
    script = tmp_path / "disposable owner.py"
    script.write_text(_OWNER, encoding="utf-8")
    env = dict(os.environ, HOME=str(tmp_path), HERMES_HOME=str(tmp_path / "home"),
               PYTHONPATH=str(Path(__file__).resolve().parents[2]))
    env.pop("_HERMES_GATEWAY", None)
    log = (tmp_path / "owners.log").open("w", encoding="utf-8")
    owners = {role: subprocess.Popen([sys.executable, str(script), str(tmp_path), role], env=env,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log)
              for role in roles}
    return owners, log


def _cleanup(owners, log, ids):
    for identity in (i for group in ids.values() for job in group.values() for i in job):
        if _alive(identity):
            psutil.Process(identity["pid"]).kill()
    for owner in owners.values():
        if owner.poll() is None:
            owner.kill()
        owner.wait(timeout=10)
    log.close()


# Commands reparent to init once their owner dies, so cleaning them up leaves this test's subtree; real
# signal delivery to real orphans is the point of the test.
@pytest.mark.live_system_guard_bypass
def test_owner_sigkill_takes_its_running_command_not_a_live_owners(tmp_path):
    owners, log = _run_owners(tmp_path, ("control", "victim"))
    ids = {}
    try:
        ids = {role: _read(tmp_path / f"{role}.json") for role in owners}
        owners["victim"].kill()  # SIGKILL: no atexit, no finally, nothing of ours runs
        owners["victim"].wait(timeout=10)

        wait_until(lambda: not any(_alive(i) for i in ids["victim"]["foreground"]), timeout=15,
                   what="the dead owner's foreground command to exit")
        assert all(_alive(i) for i in ids["control"]["foreground"]), (
            "a live owner's command was killed", ids["control"])
    finally:
        _cleanup(owners, log, ids)


def _record_calls(monkeypatch):
    from tools.environments import local as local_mod

    calls = []
    monkeypatch.setattr(local_mod, "own_process_groups", lambda pgids: calls.append(("own", list(pgids))))
    monkeypatch.setattr(local_mod, "release_process_groups", lambda pgids: calls.append(("release", list(pgids))))
    return calls


def test_a_returned_command_releases_its_group(monkeypatch, tmp_path):
    from tools.environments.local import LocalEnvironment

    calls = _record_calls(monkeypatch)
    env = LocalEnvironment(cwd=str(tmp_path), timeout=30)
    calls.clear()
    assert env.execute("echo hi")["returncode"] == 0
    assert [verb for verb, _ in calls] == ["own", "release"] and calls[0][1] == calls[1][1], calls
