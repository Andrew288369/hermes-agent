"""Long-lived stand-in for the gateway: one LAN connect per second, one JSON line each.

TEMPORARY probe, never merge. argv: ip port logfile seconds
"""
import errno
import json
import os
import socket
import sys
import time

ip, port, logfile, seconds = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
with open(logfile + ".pid", "w") as fh:
    fh.write(str(os.getpid()))
deadline = time.monotonic() + seconds
while time.monotonic() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((ip, port))
        name = "CONNECTED"
    except TimeoutError:
        name = "TIMEOUT"
    except OSError as exc:
        name = errno.errorcode.get(exc.errno, str(exc.errno))
    finally:
        sock.close()
    with open(logfile, "a") as fh:
        fh.write(json.dumps({"t": time.time(), "pid": os.getpid(), "ppid": os.getppid(),
                             "result": name}) + "\n")
    time.sleep(1)
