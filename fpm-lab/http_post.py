#!/usr/bin/env python3
"""POST a multipart body, deriving the boundary from the body's first line."""
import sys
import http.client

port = int(sys.argv[4]) if len(sys.argv) > 4 else 18120
path, bodyfile = sys.argv[1], sys.argv[2]
sid = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
body = open(bodyfile, "rb").read()
first = body.split(b"\r\n", 1)[0]
if not first.startswith(b"--"):
    raise SystemExit("body does not start with a boundary")
boundary = first[2:].decode("latin1")
headers = {
    "Content-Type": "multipart/form-data; boundary=" + boundary,
    "Content-Length": str(len(body)),
}
if sid:
    headers["Cookie"] = "PHPSESSID=" + sid
c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
try:
    c.request("POST", path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read(200)
    print("[%s] status=%d body=%r" % (path, r.status, data[:120]))
except Exception as e:
    print("[%s] ERR %s" % (path, e))
finally:
    c.close()
