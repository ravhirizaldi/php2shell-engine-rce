set pagination off
set confirm off
break php_var_unserialize_init
commands
silent
python
import gdb, struct
try:
    base = int(gdb.parse_and_eval("&basic_globals"))
    inf = gdb.selected_inferior()
    mb = inf.read_memory(base + 0x358, 8)
    d = struct.unpack("<Q", mb.tobytes())[0]
    lv = struct.unpack("<i", inf.read_memory(base + 0x360, 4).tobytes())[0]
    print("INIT pre: data=%#x level=%d stack=%#x" % (d, lv, int(gdb.parse_and_eval("$rsp"))))
except Exception as e:
    print("INIT-ERR", e)
end
continue
end
continue
