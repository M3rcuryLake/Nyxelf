from elftools.elf.elffile import ELFFile

def detect_antidebug_apis(file_path):
    suspicious_symbols = [
            {'ptrace': 'Used to prevent debugger attachment'},
            {'getppid': 'Checks if parent process is a debugger'},
            {'syscall':'Direct syscall usage to evade detection'},
            {'prctl': 'Disables ptrace for self'},
            {'sigaction': 'Modifies signal handling to disrupt debuggers'},
            {'fork': 'Creates processes to hide from debuggers'},
            {'execve': 'Re-spawns itself to avoid debugging'}
    ]

    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        symbols = []
        # Scan symbol tables
        for section in elf.iter_sections():
            if section.header['sh_type'] == 'SHT_SYMTAB':
                symtab = section
                for sym in symtab.iter_symbols():
                    if sym.name:
                        symbols.append(sym.name)

        # Match symbols
        matches = []
        for _ in suspicious_symbols:
            sym = list(_.keys())[0]
            for i in symbols:
                if sym in i:
                    matches.append(_)

        return {list(item.keys())[0]: list(item.values())[0] for item in matches}



