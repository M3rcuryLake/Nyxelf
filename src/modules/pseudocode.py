import angr
import struct
import html


def decompile(file):
    proj = angr.Project(file, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    main = proj.kb.functions['main']
    dec = proj.analyses.Decompiler(main, cfg=cfg.model)
    print('[*] Generated C - Lang Pseudocode')

    return dec.codegen.text

def read_string(memory, addr):
    """Read and decode null-terminated strings"""
    s = b""
    while True:
        b = memory.load(addr, 1)
        if b == b"\x00":
            break
        s += b
        addr += 1
    return s.decode()

def disassem_vars(file):

    """Get Variable data from binary"""

    proj = angr.Project(file, auto_load_libs=False)
    var_str = []
    for section in proj.loader.main_object.sections:
        if "data" in section.name or "rodata" in section.name or "bss" in section.name:
            if section.name == ".rodata":

                # strings
                # document this part of the code
                # fr man, i was away for few days nd i forgot how this shit works, awesome....

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
                # document this part too :(

                addr = section.vaddr
                while addr < section.vaddr + section.memsize:
                    val = proj.loader.memory.load(addr, 4)
                    int_val = struct.unpack("<I", val)[0]
                    var_str.append(f"/* Address: {hex(addr)} (.data)-> Value: {int_val} */")
                    addr += 4
    print('[*] Grabbed Assembly Instructions')
    return '\n'.join(var_str)

def construct_gen(file):
    sstr =  f"{disassem_vars(file)}\n\n\n{decompile(file)}"
    return html.escape(sstr)
