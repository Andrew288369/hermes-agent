"""macOS Local Network Privacy repro for the Desktop-attached gateway. TEMPORARY, never merge.

Question: Hermes Desktop starts the long-lived gateway as a detached child (`hermes gateway
ensure` -> Popen(start_new_session)), and the gateway outlives the app by design. Does a detached
child keep LAN access after the app responsible for it quits?

The runner cannot grant Local Network to an arbitrary app (no CLI grant path), so Terminal.app
stands in for the granted app: TN3179 exempts tools run from Terminal "including any child
processes they spawn". Legs:
  root          ground truth for what "allowed" looks like on this peer (root is exempt)
  job           the Actions job shell
  agent-bare    launchd agent running the interpreter directly (expected blocked: #71206)
  agent-osa     launchd agent through the osascript JXA wrapper (expected allowed: #71206 fix)
  term-plain    detached child of a Terminal-run script, sampled before/after Terminal quits
  term-osa      same, but the child is the osascript wrapper (the "just wrap it" candidate)

argv: outdir prober_python
"""
import errno
import json
import os
import plistlib
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
PY = sys.argv[2]
HERE = Path(__file__).resolve().parent
UID = os.getuid()
HOSTILE = "EHOSTUNREACH"


def sh(cmd, timeout=30):
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def log(msg):
    print(msg, flush=True)
    with (OUT / "driver.log").open("a") as fh:
        fh.write(msg + "\n")


def result(leg, **fields):
    log("RESULT " + json.dumps({"leg": leg, **fields}))


def responsible(pid):
    _, text = sh(["sudo", "-n", "launchctl", "procinfo", str(pid)])
    lines = [ln.strip() for ln in text.splitlines() if "responsible" in ln.lower()]
    return lines or [text[-300:]]


def check(prefix=()):
    _, text = sh([*prefix, PY, str(HERE / "check.py"), IP, str(PORT)], timeout=15)
    try:
        return json.loads(text.splitlines()[-1])["result"]
    except (ValueError, IndexError, KeyError):
        return f"ERR:{text[-200:]}"


def read_log(path):
    try:
        return [json.loads(ln) for ln in Path(path).read_text().splitlines() if ln.strip()]
    except OSError:
        return []


def tally(rows):
    out = {}
    for row in rows:
        out[row["result"]] = out.get(row["result"], 0) + 1
    return out


def wait_for(path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if Path(path).exists() and Path(path).stat().st_size:
            return True
        time.sleep(0.5)
    return False


# ── environment facts ────────────────────────────────────────────────────────
for label, cmd in [
    ("sw_vers", ["sw_vers"]),
    ("csrutil", ["csrutil", "status"]),
    ("lnp_defaults", ["sudo", "-n", "defaults", "read", "com.apple.network.local-network"]),
    ("prober_python", ["/bin/sh", "-c", f"ls -l {shlex.quote(PY)}; codesign -dv {shlex.quote(os.path.realpath(PY))} 2>&1 | head -5"]),
    ("ancestry", ["/bin/sh", "-c", "p=$$; while [ \"$p\" -gt 1 ]; do ps -o pid=,ppid=,user=,command= -p $p | cut -c1-160; p=$(ps -o ppid= -p $p | tr -d ' '); done"]),
    ("gui_session", ["launchctl", "print", f"gui/{UID}"]),
]:
    code, text = sh(cmd)
    if label == "gui_session":
        text = "\n".join(text.splitlines()[:6])
    log(f"FACT {label} (exit {code}):\n{text}\n")
log("FACT driver responsible: " + json.dumps(responsible(os.getpid())))

# ── pick a LAN peer: root (exempt) must reach it without EHOSTUNREACH ────────
_, route = sh(["route", "-n", "get", "default"])
gateway = re.search(r"gateway:\s*(\S+)", route)
iface = re.search(r"interface:\s*(\S+)", route)
_, arp = sh(["arp", "-an"])
candidates = ([gateway.group(1)] if gateway else []) + re.findall(r"\((\d+\.\d+\.\d+\.\d+)\)", arp)
log(f"FACT default route iface={iface and iface.group(1)} candidates={candidates}")
IP = PORT = None
fallback = None
for ip in dict.fromkeys(candidates):
    if ip.endswith(".255") or ip.startswith("224."):
        continue
    for port in (53, 22, 80, 443, 8080, 5900):
        IP, PORT = ip, port
        got = check(("sudo", "-n"))
        log(f"PEER root {ip}:{port} -> {got}")
        if got in ("CONNECTED", "ECONNREFUSED"):
            break
        if got != HOSTILE and fallback is None:
            fallback = (ip, port)
    else:
        continue
    break
else:
    if fallback is None:
        result("setup", error="no LAN peer reachable even as root")
        sys.exit(0)
    IP, PORT = fallback
ROOT = check(("sudo", "-n"))
result("root", peer=f"{IP}:{PORT}", got=ROOT)
result("job", got=check(), responsible=responsible(os.getpid()))


# ── launchd agent legs ───────────────────────────────────────────────────────
def agent_leg(leg, mode):
    label = f"com.hermes.lnpprobe.{leg}"
    logfile = OUT / f"loop-{leg}.jsonl"
    loop_cmd = [PY, str(HERE / "loop.py"), IP, str(PORT), str(logfile), "8"]
    if mode == "bare":
        args = loop_cmd
    else:
        shell = f"exec {shlex.join(loop_cmd)} >> {shlex.quote(str(logfile) + '.out')} 2>> {shlex.quote(str(logfile) + '.err')}"
        javascript = ('ObjC.import("stdlib"); '
                      f"const status=$.system({json.dumps(shell)}); "
                      "const signal=status & 127; "
                      "$.exit(status === -1 ? 1 : signal === 0 ? (status >> 8) & 255 : 128 + signal);")
        args = ["/usr/bin/osascript", "-l", "JavaScript", "-e", javascript]
    plist = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_bytes(plistlib.dumps({
        "Label": label, "ProgramArguments": args, "RunAtLoad": True,
        "StandardOutPath": str(OUT / f"{leg}.launchd.out"),
        "StandardErrorPath": str(OUT / f"{leg}.launchd.err"),
    }))
    domain = f"gui/{UID}"
    code, text = sh(["launchctl", "bootstrap", domain, str(plist)])
    if code != 0:
        domain = f"user/{UID}"
        code, text = sh(["launchctl", "bootstrap", domain, str(plist)])
    if code != 0:
        result(leg, error=f"bootstrap failed: {text[-200:]}")
        return
    pid_seen = wait_for(str(logfile) + ".pid", 20)
    resp = responsible(Path(str(logfile) + ".pid").read_text().strip()) if pid_seen else ["no pid"]
    time.sleep(9)
    sh(["launchctl", "bootout", f"{domain}/{label}"])
    plist.unlink(missing_ok=True)
    result(leg, domain=domain, samples=tally(read_log(logfile)), responsible=resp)


agent_leg("agent-bare", "bare")
agent_leg("agent-osa", "osascript")

# ── Terminal legs: detached children outliving the responsible app ──────────
command = OUT / "leg.command"
marker = OUT / "terminal.marker"
command.write_text(
    "#!/bin/bash\n"
    f"{shlex.quote(PY)} {shlex.quote(str(HERE / 'spawn.py'))} {shlex.quote(PY)} {IP} {PORT} {shlex.quote(str(OUT))} 45 plain\n"
    f"{shlex.quote(PY)} {shlex.quote(str(HERE / 'spawn.py'))} {shlex.quote(PY)} {IP} {PORT} {shlex.quote(str(OUT))} 45 osascript\n"
    f"echo $$ > {shlex.quote(str(marker))}\n"
    "exit 0\n"
)
command.chmod(0o755)
sh(["killall", "Terminal"])
code, text = sh(["open", "-a", "Terminal", str(command)])
if code != 0 or not wait_for(marker, 40):
    result("terminal", error=f"Terminal never ran the script (open exit {code}: {text[-200:]})")
else:
    plain, osa = OUT / "loop-plain.jsonl", OUT / "loop-osascript.jsonl"
    wait_for(str(plain) + ".pid", 15)
    wait_for(str(osa) + ".pid", 15)
    _, term_pids = sh(["pgrep", "-x", "Terminal"])
    pids = {m: Path(str(p) + ".pid").read_text().strip() for m, p in (("plain", plain), ("osascript", osa))
            if Path(str(p) + ".pid").exists()}
    before_resp = {m: responsible(pid) for m, pid in pids.items()}
    time.sleep(8)
    kill_at = time.time()
    sh(["killall", "-TERM", "Terminal"])
    for _ in range(20):
        if sh(["pgrep", "-x", "Terminal"])[0] != 0:
            break
        time.sleep(0.5)
    else:
        sh(["killall", "-KILL", "Terminal"])
    gone = sh(["pgrep", "-x", "Terminal"])[0] != 0
    after_resp = {m: responsible(pid) for m, pid in pids.items()}
    time.sleep(12)
    reopen_at = time.time()
    sh(["open", "-a", "Terminal"])  # a NEW instance, like reopening Desktop
    time.sleep(10)
    for mode, path in (("plain", plain), ("osascript", osa)):
        rows = read_log(path)
        result(f"term-{mode}", terminal_pids=term_pids.split(), terminal_gone=gone,
               before_quit=tally([r for r in rows if r["t"] < kill_at]),
               after_quit=tally([r for r in rows if kill_at <= r["t"] < reopen_at]),
               after_reopen=tally([r for r in rows if r["t"] >= reopen_at]),
               responsible_before=before_resp.get(mode), responsible_after=after_resp.get(mode))
    sh(["killall", "Terminal"])

code, text = sh(["log", "show", "--last", "5m", "--style", "compact", "--predicate",
                 'process == "nehelper" OR subsystem == "com.apple.networkextension"'], timeout=120)
(OUT / "nehelper.log").write_text(text)
log(f"FACT nehelper log lines: {len(text.splitlines())} (artifact nehelper.log)")
log("DONE")
