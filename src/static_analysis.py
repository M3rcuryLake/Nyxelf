import subprocess

#
#  parses the output of readelf, objdump and other modules and converts it
#  to a json like output, which is then converted to a html table
#

from src.modules.section_entropy import analyze_elf_sections
from src.modules.variables import extract_var_data
from src.modules.packer_detection import detect_packer
from src.modules.anti_debug_apis import detect_antidebug_apis


def header(file):
    data = subprocess.run(["readelf", "-h", file, "-W"], text=True, capture_output=True).stdout
    header_data = dict()
    for _ in data.splitlines():
       key, value = _.split(":")
       key = key.strip()
       value = value.strip()
       if value.isdigit():
           value = int(value)
       header_data[key] = value
    header_data.pop("ELF Header")

    filedata = subprocess.run(["file", file], text=True, capture_output=True).stdout
    filedata = filedata.split(",")
    if ' not stripped\n' in filedata:
        header_data["Stripped File"] = False
    else:
        header_data["Stripped File"] = True


    print("[*] Parsed Header Data")

    
    return header_data    

def sections(file):
    data = subprocess.run(["readelf", "-S", file, "-W"], text=True, capture_output=True).stdout
    if data.strip() != "There are no sections in this file." :
        section_list, parsed_list, section_data = [[] for _ in range(3)]
        data_keys = ["Name", "Type", "Address", "Offset", "Size", "Entry Size", "Flags", "Link", "Info", "Alignment"]
        for _ in data.splitlines():
            if _.startswith("  ["):
                section_list.append(_)
        section_list = section_list[2:]
        for _i in section_list:
            _i = _i.split(" ")
            while '' in _i:
                _i.remove('')
            if _i[0] == "[" :
                _i = _i[2:]
            else :
                _i = _i[1:]
            if len(_i) < 10:
                _i.insert(6, "Unknown")
            if len(_i)>10 and _i[7] in "WAXMSILOGTCxoEDlp":
                _i[6] = _i[6] + _i[7]
                _i.pop(7)
            parsed_list.append(_i)
        for _j in parsed_list:
            _j = dict(zip(data_keys, _j))
            section_data.append(_j)

        output = []
        entropy_data = analyze_elf_sections(file)
        for item in section_data:
            key = item['Name']
            if key in entropy_data: 
                item['Entropy'] = entropy_data[key] 
            output.append(item) 
    elif data.strip() == "There are no sections in this file." :
        output = "No Section data found in the file, file is possibly manipulated or packed"
    else :
        output = "An Unknown Error Occured"

    print("[*] Parsed Section Data")

    return output

    #TODO :permissions of each sections in complete words instead of WAX format

def program_headers(file):
    data = subprocess.run(["readelf","-l", file, "-W"], text=True, capture_output=True).stdout
    data = data.splitlines()
    start = data.index("Program Headers:")
    if " Section to Segment mapping:" not in data : 
        data = data[start:]
    else:
        end = data.index(" Section to Segment mapping:")
        data = data[start+2:end-1]
    header_keys = ['Type', 'Offset', 'Virtual Address', 'Physical Address', 'File Size', 'Memory Size', 'Flags', 'Alignment']
    program_headers = []
    for _ in data:
        if 'Requesting' not in _:
            _ = _.split(' ')
            while '' in _:
                _.remove('')
            if len(_)>7 and _[7] in "WAXMSILOGTCxoEDlp":
                _[6] = _[6] + _[7]
                _.pop(7)
            _ = dict(zip(header_keys, _))
            program_headers.append(_)

    print("[*] Parsed Program Headers")

    return program_headers
            

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
        shared_libraries = ["Could'nt retrive Shared Libraries"]
    return shared_libraries


def dyn_syms(file):
    data = subprocess.run(["readelf","--dyn-syms", file, "-W"], text=True, capture_output=True).stdout
    if len(data)!=0:
        data = data.splitlines()[3:]
        table_keys = ["Offset Value", "Size", "Type", "Symbol Binding", "Visibility", "Section Index" , "Name"]
        dyn_sym_table = []
        for _ in data:
            _ = _.split(' ')
            while '' in _ :
                _.remove('')
            _.pop(0)
            _ = dict(zip(table_keys, _))
            dyn_sym_table.append(_)
    else:
        dyn_sym_table = ["Couldn't retrive the Dynamic Symbols table "]

    print("[*] Parsed Dynamic Symbols table")

    return dyn_sym_table
        
    

def functions(file):
    command = f"objdump -d {file} | grep '<.*>:'"
    map = ["Offset Value", "Function"]
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    function_table = []
    if stdout:
        output = stdout.decode()
        output = output.splitlines()

        for _ in output:
            _ = _.split(' ')
            _[-1]= _[-1][1:-2]
            _ = dict(zip(map, _))
            function_table.append(_)

    if stderr:
        raise ValueError

    print("[*] Parsed Functions")

    return function_table


def variable_data(file):
    header_dict = header(file)
    if "little" in header_dict['Data']:
        endian = "little"
    else :
        endian = "big"
    vars = extract_var_data(file, endian)
    if len(vars) == 0:
        vars = ['No Varibles are defined in the .data section']

    print("[*] Parsed Variable Data")
    return vars


def antidebug_apis(file):
    apis = detect_antidebug_apis(file)
    if len(apis) == 0:
        apis = ['No Suspicious Apis Detected']
    print("[*] Analysed APIs")
    return apis


def packer(file, arg):
    
    print("[*] Analysing Packer data")
    return detect_packer(file, arg)



# TODO:
#def patch_ptrace(arg):
#    pass
#


def data(file, unpack):
    table = ['<h2>Header Information</h2>', '<h2>Packer Info</h2>', '<h2>Sections</h2>', '<h2>Program Headers</h2>', '<h2>Shared Libraries</h2>', '<h2>Dynamic Symbols</h2>', '<h2>Functions</h2>', '<h2>Variable Data</h2>', '<h2>Suspicious APIs<h2>']

    vars = [header(file),
        packer(file, unpack),
        sections(file),
        program_headers(file),
        shared_libraries(file),
        dyn_syms(file),
        functions(file),
        variable_data(file),
        antidebug_apis(file)
        ]
    data = dict(zip(table, vars))

    return data

