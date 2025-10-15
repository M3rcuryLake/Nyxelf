import subprocess
from math import log2
from os.path import getsize
import hashlib
from elftools.elf.elffile import ELFFile


from src.modules.variables import disassem_vars
from src.modules.packer_detection import detect_packer
from src.modules.anti_debug_apis import detect_antidebug_apis


def hash(data):
    data = data.encode('utf-8')
    """Return MD5, SHA1, and SHA256 hex digests of data."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }



def entropy(data):
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    length = len(data)
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * log2(p)

    return entropy

def file_info(file_path, packer_arg):
    fi_data = dict()
    packer_inf = detect_packer(file_path, packer_arg)
    fid = ''
    with open(file_path, 'rb') as f:
        hashdir = hash(file_path)
        fi_data["Size"] = str(getsize(file_path))+"b"
        fi_data["SHA-1"] = hashdir["sha1"]
        fi_data["SHA-256"] = hashdir['sha256']
        fi_data["MD5"] = hashdir['md5']
        fi_data["Packer Info"] = packer_inf["Packer"]
        fi_data["Packer Note"] = packer_inf["Note"]
    
    for key, value in fi_data.items():
        fid +=f'<p><span class="text-gray-400">{key} : <span class ="text-sm text-green-400">{value}</span>\n'

    print("[*] Extracted Basic File Info")
    return fid


def header(file_path):
    header_data = dict()
    headerd = '' 
    with open(file_path, 'rb') as f:
        header_data["File Entropy"] = f"{entropy(f.read()):.4f}"

        elf = ELFFile(f)
        ehdr = elf.header
        header_data["Class"] = 'ELF64' if ehdr['e_ident']['EI_CLASS'] == 'ELFCLASS64' else 'ELF32'
        header_data["Data"] = ehdr['e_ident']['EI_DATA']
        header_data["Version"] = ehdr['e_ident']['EI_VERSION']
        header_data["OS/ABI"] = ehdr['e_ident']['EI_OSABI']
        header_data["Type"] = ehdr['e_type']
        header_data["Machine"] = ehdr['e_machine']
        header_data["Entry point"] = hex(ehdr['e_entry'])
        header_data["Program Header Offset"] = hex(ehdr['e_phoff'])
        header_data["Section Header Offset"] = hex(ehdr['e_shoff'])
        header_data["Flags"] = ehdr['e_flags']
        header_data["Header Size"] = ehdr['e_ehsize']
        header_data["Program Header Size"] = ehdr['e_phentsize']
        header_data["Program Header Count"] = ehdr['e_phnum']
        header_data["Section Header Size"] = ehdr['e_shentsize']
        header_data["Section Header Count"] = ehdr['e_shnum']
        header_data["Section Header String Table Index"] = ehdr['e_shstrndx']
        symtab = elf.get_section_by_name('.symtab')
        header_data["Stripped File"] = symtab is None
    
    for key, value in header_data.items():
        headerd +=f'<p><span class="text-gray-400">{key} : </span>{value}</p>\n'
    
    print("[*] Grabbed Header Information")
    return headerd


def symbols(elf):

    """
    Extracts and formats detailed symbol and section information from an ELF binary.

    Parameters
    ----------
    elf : elftools.elf.elffile.ELFFile
        Parsed ELF object from the pyelftools library.

    Returns
    -------
    list[str]
        A list of four formatted string blocks:
        |__symtable : str
        |__dyntable : str
        |__funcs : str
        |__secs : str
    """

    symtable, dyntable, funcs, secs = "","","","" 

    # --------- 1. Normal Symbols (from .symtab) ---------
    symtab = elf.get_section_by_name('.symtab')
    if symtab:
        for sym in symtab.iter_symbols():
            sname = sym.name
            if len(sname) > 25 :
                sname = sname[:25]
            elif sname == '':
                sname = '(null)'
            symtable += f'<li class="flex px-2 py-1 rounded hover:bg-[#2c2c2c] cursor-pointer"><p class="text-sm">{sname}</p><p class="text-blue-400 text-xs mx-5">({sym["st_size"]}b)</p><p class="text-xs text-amber-500"> (A:{hex(sym["st_value"])})<p></li>\n'
        print("[*] Grabbed Symbols from the executable")
    else:
        symtable = "[!] No .symtab section found (binary may be stripped)"

    # --------- 2. Dynamic Symbols (from .dynsym) ---------
    dynsym = elf.get_section_by_name('.dynsym')
    if dynsym:
        for sym in dynsym.iter_symbols():
            sname = sym.name
            if len(sname) > 25 :
                sname = sname[:25]
            elif sname == '':
                sname = '(null)'

            dyntable += f'<li class="flex px-2 py-1 rounded hover:bg-[#2c2c2c] cursor-pointer"><p class="text-sm">{sname}</p><p class="text-blue-400 text-xs mx-5">({sym["st_size"]}b)</p><p class="text-xs text-amber-500"> (A:{hex(sym["st_value"])})<p></li>\n'
        print("[*] Grabbed Dynamic Symbols")
    else:
        dyntable = "[!] No .dynsym section found"

    # --------- 3. Functions ---------
    for section in [symtab, dynsym]:
        if section:
            for sym in section.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC' and sym.name:
                    funcs += f"Func: {sym.name:<30} | Addr: {hex(sym['st_value'])}\n"
    print("[*] Extracted Function Information")

    # --------- 4. Sections ---------
    for section in elf.iter_sections():
        data = section.data()
        e = entropy(data)
        secs += f"{section.name:<20} Size = {len(data):<6}  Entropy = {e:.4f}\n"
    print("[*] Grabbed Section data")

    return [symtable, dyntable, funcs, secs]


def shared_libraries(file):
    data = subprocess.run(["readelf","-d", file, "-W"], text=True, capture_output=True).stdout

    if data.strip()!="There is no dynamic section in this file.":

        data = data.splitlines()
        shared_libraries = []
        for _ in data:
            if "NEEDED" in _:
                _ = _.split(' ')
                while '' in _ :
                    _.remove('')
                shared_libraries.append(_[-1])
    else:
        shared_libraries = ["Could not retrive Shared Libraries"]
    return shared_libraries

def variable_data(file):
    vars = disassem_vars(file)
    if len(vars) == 0:
        vars = ['No Varibles are found']

    print("[*] Parsed Variable Data")
    return vars


def antidebug_apis(file):
    apis = detect_antidebug_apis(file)
    if len(apis) == 0:
        apis = ['No Suspicious Apis Detected']
    print("[*] Analysed APIs")
    return apis


def data(file, unpack):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        fi_table = file_info(file, unpack)
        header_table = header(file)
        symbol_table, dynsym_table, function_table, section_table = symbols(elf)
        variable_table = variable_data(file)

    return fi_table, header_table, symbol_table, dynsym_table, function_table, section_table, variable_table


