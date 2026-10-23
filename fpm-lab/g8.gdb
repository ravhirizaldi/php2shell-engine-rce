set pagination off
set confirm off
break var_tmp_var
commands
silent
python
import gdb, struct
try:
    vh = int(gdb.parse_and_eval("$rdi"))
    inf = gdb.selected_inferior()
    d = struct.unpack("<Q", inf.read_memory(vh, 8).tobytes())[0]
    try:
        head = inf.read_memory(d, 32).tobytes()
    except Exception:
        head = b""
    found = []
    scan = []
    for off in range(0x40000, 0, -0x1000):
        try:
            m = inf.read_memory(d - off, 0x1000).tobytes()
        except Exception:
            continue
        i = m.find(b"blob|s:")
        if i >= 0:
            found.append((hex(d - off + i), hex(off - i)))
        if b"blob|s:" in m:
            scan.append(hex(off))
    marker = head[:8].hex()
    print("VARTMP vh=%#x d=%#x head=%s blob=%s" % (vh, d, marker, found))
except Exception as e:
    print("VARTMP-ERR", e)
end
continue
end
handle SIGSEGV stop print
continue
bt 4
