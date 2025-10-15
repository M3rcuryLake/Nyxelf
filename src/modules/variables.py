import r2pipe
import angr
import json
import struct


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


def dbg_chk(r2):
    r2.cmd("aaa")
    sections = r2.cmdj("iSj")
    debug_secs = [s for s in sections if s['name'].startswith('.debug')]
    
    return debug_secs if debug_secs else False


def globalv(r2):

    '''
    Runs a full analysis (`aaa`) to resolve symbols and relocations.
    Filters symbols of type `OBJ` (radare2’s classification for global variables).
    Ignores compiler-generated and bookkeeping symbols (e.g. those starting with `_` or named `completed.0`).
    Reads the raw bytes at each symbol’s virtual address, then:
      * If the size is **4 bytes**, unpacks it as a little-endian unsigned 32-bit integer (`<I`).
      * If the size is **8 bytes**, unpacks it as a little-endian unsigned 64-bit integer (`<Q`).
      * Otherwise, attempts to interpret the data as a UTF-8 string, falling back to raw bytes if decoding fails.
    Returns a newline-separated string describing each variable
    '''

    gvars = ''

    r2.cmd("aaa")
    symbols = json.loads(r2.cmd("isj"))

    for sym in symbols:
        if sym.get("type") == "OBJ" and sym.get("name").startswith("_") != True and sym.get("name")!='completed.0':
            name = sym.get("name")
            addr = sym.get("vaddr")
            size = sym.get("size", 0)

            # read raw bytes
            raw = r2.cmdj(f"pxj {size} @ {addr}")

            val = None
            if size == 4:
                val = struct.unpack("<I", bytes(raw))[0]
            elif size == 8:
                val = struct.unpack("<Q", bytes(raw))[0]
            else:
                try:
                    val = bytes(raw).decode(errors="ignore")
                except:
                    val = raw
    
            gvars += f"[*] Addr: {hex(addr)} (.global)-> Name: {name:<5} Size: {size:<5} Value: {val}\n"

    return gvars

def localv(file):
    """Get Variable data from binary"""

    proj = angr.Project(file, auto_load_libs=False)
    var_str = []
    for section in proj.loader.main_object.sections:
        if "data" in section.name or "rodata" in section.name or "bss" in section.name:
            if section.name == ".rodata":

                '''
                Scan .rodata section
                .rodata typically stores read-only constants: C-strings, const arrays, etc.
                We attempt to extract null-terminated ASCII/UTF-8 strings.
                '''

                addr = section.vaddr
                while addr < section.vaddr + section.memsize:
                    try:
                        s = read_string(proj.loader.memory, addr)
                        lens = len(s)
                        if lens != 0:
                            var_str.append(f"[*] Addr: {hex(addr)} (.rodata)-> Size: {lens:<5} Value: {(s.encode('utf-8'))} ")
                        addr += lens + 1
                    except:
                        addr += 1

    return '\n'.join(var_str)


def disassem_vars(binary):

    ''' Extract and display both global and local variable data from a binary. '''

    vars = ''
    r2 = r2pipe.open(binary, flags=["-e", "bin.cache=true"])
    if dbg_chk(r2):
        vars += "Debug Information Available\n"
    vars += globalv(r2)
    vars += localv(binary)
    print('[*] Grabbed Variable Data')
    return vars


