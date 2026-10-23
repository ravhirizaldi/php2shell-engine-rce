set pagination off
set confirm off
break php_var_unserialize
commands
silent
python
import gdb, struct
try:
    inf = gdb.selected_inferior()
    rval = int(gdb.parse_and_eval("$rdi")); pp = int(gdb.parse_and_eval("$rsi"))
    mx = int(gdb.parse_and_eval("$rdx")); vh = int(gdb.parse_and_eval("$rcx"))
    cur = struct.unpack("<Q", inf.read_memory(pp, 8).tobytes())[0]
    try:
        head = inf.read_memory(cur, 12).tobytes()
    except Exception:
        head = b"?"
    d = 0
    try:
        d = struct.unpack("<Q", inf.read_memory(vh, 8).tobytes())[0]
    except Exception:
        pass
    print("UNSER p=%#x cur=%#x d=%#x head=%s" % (pp, cur, d, head.hex()))
except Exception as e:
    print("UNSER-ERR", e)
end
continue
end
handle SIGSEGV stop print
continue
bt 8
print $rip
python
import gdb
print("rip-file-offset: " + hex(int(gdb.parse_and_eval("$rip")) - int(gdb.parse_and_eval("&basic_globals")) + 0x161c580))
end
