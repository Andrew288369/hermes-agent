"""One TCP connect to a LAN peer; prints one JSON line. TEMPORARY probe, never merge."""
import errno
import json
import os
import socket
import sys
import time

ip, port = sys.argv[1], int(sys.argv[2])
start = time.monotonic()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect((ip, port))
    name = "CONNECTED"
except TimeoutError:
    name = "TIMEOUT"
except OSError as exc:
    name = errno.errorcode.get(exc.errno, str(exc.errno))
finally:
    sock.close()
print(json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "result": name,
                  "ms": round((time.monotonic() - start) * 1000)}), flush=True)
