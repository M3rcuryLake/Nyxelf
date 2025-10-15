from elftools.elf.elffile import ELFFile
from capstone import *

def disassemble(path):

    '''
    Disassembles an ELF binary and groups instructions by function name,
    similar to `objdump -d`.  

    Args:
        elf_path (str): Path to the ELF binary.

    Returns:
        str: Formatted assembly with function labels and instructions.

    '''
    
    sym_str = '''
    <li class="flex px-2 py-1 rounded hover:bg-[#2c2c2c] cursor-pointer">
    <p class="text-sm">{name}</p>
    <p class="text-blue-400 text-xs mx-5">{size}</p>
    <p class="text-xs text-amber-500">{stt}<p>
    </li>
    '''

    func_str = '''
    <li class="flex px-2 py-1 rounded hover:bg-[#2c2c2c] cursor-pointer">
    <p class="text-sm">{name}</p>
    <p class="text-blue-400 text-xs mx-5">Size : {size}</p>
    <p class="text-xs text-amber-500">Addr : {addr}<p>
    </li>
    '''

    print("[*] Attempting to Disassemble binary to Assembly...")
    with open(path, 'rb') as f:
        elf = ELFFile(f)

        arch = elf.get_machine_arch()
        if arch == 'x86':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch == 'x64':
            md = Cs(CS_ARCH_X86, CS_MODE_64)

        else:
            raise ValueError(f"[*] Unsupported arch: {arch}")
        md.syntax = CS_OPT_SYNTAX_INTEL
        md.detail = True


        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            raise ValueError("[*] No symbol table found (binary may be stripped).")


        functions = []; symbols = []; func_list = []
        for sym in symtab.iter_symbols():
            symbols.append(sym_str.format(name = sym.name, stt = sym['st_info']['type'], size = sym.entry['st_size']))

            if sym['st_info']['type'] == 'STT_FUNC' and sym.entry['st_size'] > 0:
                func_list.append(func_str.format(
                    name = sym.name,
                    addr = sym.entry['st_value'],
                    size = sym.entry['st_size']
                ))
                functions.append({
                    'name': sym.name,
                    'addr': sym.entry['st_value'],
                    'size': sym.entry['st_size']
                })


        functions.sort(key=lambda x: x['addr'])


        text_section = elf.get_section_by_name('.text')
        text_data = text_section.data()
        text_addr = text_section['sh_addr']


        output = []
        for fn in functions:
            fn_start = fn['addr']
            fn_end = fn_start + fn['size']


            if fn_start < text_addr or fn_end > text_addr + len(text_data):
                continue


            offset = fn_start - text_addr
            fn_bytes = text_data[offset: offset + fn['size']]

            output.append(f"\n{fn['addr']:016x} <{fn['name']}>:")

            for ins in md.disasm(fn_bytes, fn_start):
                output.append(f"    {ins.address:016x}:\t{ins.mnemonic}\t{ins.op_str}")

        print("[*] x86_64 Intel Assembly Generated.")
        return "\n".join(output), "\n".join(symbols), "\n".join(func_list)

