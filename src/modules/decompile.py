from elftools.elf.elffile import ELFFile
from capstone import *

def disassemble_elf(filename):
    '''
    usage : disassemble_elf(filename)
    '''
    opc_list = []
    with open(filename, "rb") as f:
        elf = ELFFile(f)
        arch = CS_ARCH_X86
        mode = CS_MODE_64 
        # disassm sections to find the .text section
        for section in elf.iter_sections():
            if section.name == ".text":  
                code = section.data()
                addr = section['sh_addr']
                
                opc_list.append('Entry Point:'+ hex(elf.header['e_entry']))

                
                md = Cs(arch, mode)
                md.detail = True
                
                ###
                for insn in md.disasm(code, addr):
                    opc_list.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
                break
        else:
            opc_list.append("No .text section found.")

    return '\n'.join(opc_list)


