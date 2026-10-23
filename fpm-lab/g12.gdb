set pagination off
set confirm off
set $hits = 0
break var_tmp_var
commands
silent
set $hits = $hits + 1
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
    hits = int(gdb.parse_and_eval("$hits"))
    found = None
    meta = ""
    if hits <= 8:
        for delta in range(-0x400000, 0x200001, 0x40000):
            try:
                m = inf.read_memory(d + delta, 0x40000).tobytes()
            except Exception:
                continue
            i = m.find(b'p|s:')
            if i < 0:
                i = m.find(b'pad|s:')
            if i >= 0:
                addr = d + delta + i
                found = (hex(addr), "d%+d" % (delta + i), "fileoff_if_base=%#x" % (d - addr))
                break
        try:
            last = struct.unpack("<Q", inf.read_memory(d, 8).tobytes())[0]
            used = struct.unpack("<Q", inf.read_memory(d + 56, 8).tobytes())[0]
            first = struct.unpack("<Q", inf.read_memory(d + 72, 8).tobytes())[0]
            meta = "last=%#x used=%#x data0=%#x" % (last, used, first)
        except Exception:
            pass
    print("VARTMP#%d vh=%#x d=%#x head=%s %s marker=%s" % (hits, vh, d, head[:8].hex(), meta, found))
except Exception as e:
    print("VARTMP-ERR", e)
end
continue
end
break system
commands
silent
printf "SYSTEM rdi=%p cmd=%s\n", $rdi, (char*)$rdi
continue
end
break rc_dtor_func if ((*(unsigned int*)($rdi+4)) & 0xf) == 10
commands
silent
printf "RCDTOR ref=%p rc=%u type=%u\n", $rdi, *(unsigned int*)$rdi, (*(unsigned int*)($rdi+4)) & 0xf
continue
end
handle SIGSEGV stop print
continue
bt 8
