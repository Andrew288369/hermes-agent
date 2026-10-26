"""Start loop.py detached the way `hermes gateway ensure` starts the gateway
(hermes_cli/gateway_runtime_start.py::spawn_unmanaged_gateway: Popen + start_new_session,
devnull stdio). TEMPORARY probe, never merge.

argv: python ip port outdir seconds mode   (mode: plain | osascript)
"""
import json
import shlex
import subprocess
import sys

py, ip, port, outdir, seconds, mode = sys.argv[1:7]
here = __file__.rsplit("/", 1)[0]
log = f"{outdir}/loop-{mode}.jsonl"
command = [py, f"{here}/loop.py", ip, port, log, seconds]
if mode == "osascript":
    # Same shape as hermes_cli/gateway_launchd.py::launchd_program_arguments.
    shell = f"exec {shlex.join(command)} >> {shlex.quote(log + '.out')} 2>> {shlex.quote(log + '.err')}"
    javascript = (
        'ObjC.import("stdlib"); '
        f"const status=$.system({json.dumps(shell)}); "
        "const signal=status & 127; "
        "$.exit(status === -1 ? 1 : signal === 0 ? (status >> 8) & 255 : 128 + signal);"
    )
    command = ["/usr/bin/osascript", "-l", "JavaScript", "-e", javascript]
subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
