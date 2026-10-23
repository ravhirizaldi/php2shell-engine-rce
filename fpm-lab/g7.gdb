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
        mem = inf.read_memory(d, 64).tobytes()
        print("VARTMP vh=%#x d=%#x mem=%s" % (vh, d, mem.hex()))
    except Exception as e:
        print("VARTMP vh=%#x d=%#x unreadable(%s)" % (vh, d, e))
except Exception as e:
    print("VARTMP-ERR", e)
end
continue
end
handle SIGSEGV stop print
continue
bt 6
x/8gx $rdi
