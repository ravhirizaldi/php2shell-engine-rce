set pagination off
set confirm off
python
import gdb, struct
inf = gdb.selected_inferior()
ps = int(gdb.parse_and_eval("&ps_globals"))
def q(off):
    return struct.unpack("<Q", inf.read_memory(ps + off, 8).tobytes())[0]
def i32(off):
    return struct.unpack("<i", inf.read_memory(ps + off, 4).tobytes())[0]
def u8(off):
    return struct.unpack("<B", inf.read_memory(ps + off, 1).tobytes())[0]
sid = q(0x10)
print("PS globals @ %#x id=%#x send_cookie=%d status=%d" % (ps, sid, u8(0x178), i32(0x98)))
try:
    if sid:
        rc = struct.unpack("<I", inf.read_memory(sid, 4).tobytes())[0]
        typ = struct.unpack("<I", inf.read_memory(sid + 4, 4).tobytes())[0] & 0xff
        ln = struct.unpack("<Q", inf.read_memory(sid + 0x10, 8).tobytes())[0]
        data = inf.read_memory(sid + 0x18, min(32, ln)).tobytes()
        print("  idstr=%#x rc=%d type=%d len=%d data=%r" % (sid, rc, typ, ln, data))
except Exception as e:
    print("  id read error:", e)
end
detach
quit
