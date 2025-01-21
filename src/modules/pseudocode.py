import angr
import struct


def decompile(file):
    proj = angr.Project(file, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    main = proj.kb.functions['main']
    dec = proj.analyses.Decompiler(main, cfg=cfg.model)

    return dec.codegen.text

def read_string(memory, addr):
    """Read null-terminated string from memory."""
    s = b""
    while True:
        b = memory.load(addr, 1)
        if b == b"\x00":
            break
        s += b
        addr += 1
    return s.decode()

def disassem_vars(file):
    proj = angr.Project(file, auto_load_libs=False)
    var_str = []
    for section in proj.loader.main_object.sections:
        if "data" in section.name or "rodata" in section.name or "bss" in section.name:
            if section.name == ".rodata":
                # strings
                addr = section.vaddr
                while addr < section.vaddr + section.memsize:
                    try:
                        s = read_string(proj.loader.memory, addr)
                        var_str.append(f"/* Address: {hex(addr)} (.rodata)-> String: {s} */")
                        addr += len(s) + 1
                    except:
                        addr += 1

            elif section.name == ".data":
                # integers
                addr = section.vaddr
                while addr < section.vaddr + section.memsize:
                    val = proj.loader.memory.load(addr, 4)
                    int_val = struct.unpack("<I", val)[0]
                    var_str.append(f"/* Address: {hex(addr)} (.data)-> Value: {int_val} */")
                    addr += 4
    return '\n'.join(var_str)

def construct_gen(file):
    sstr =  f"{disassem_vars(file)}\n\n\n{decompile(file)}"
    return sstr

#print(construct_gen('./test'))
