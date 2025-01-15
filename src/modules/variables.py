from elftools.elf.elffile import ELFFile
import subprocess
import struct



def str_break(string):

    """Breaks a string into chunks of 20 characters for readability."""

    spaced_string = []
    for _ in range(0, len(string), 20):
        spaced_string.append(string[_:_+20])

    
    return ' '.join(spaced_string)


def extract_var_data(filename, ENDIAN):

    """Extracts variable data from an ELF file, including address, size, and inferred values."""

    if ENDIAN == "little":
        prefix = "<"
    if ENDIAN == "big":
        prefix= ">"

    def get_var_addr(filename):
        """Retrieves variable addresses and sizes using readelf."""

        command = f"readelf -s {filename} | grep 'OBJECT'"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stdout:
            output = stdout.decode()
        output = output.splitlines()
        var_data =[]

        for _ in output:
            _ = _.split(' ')
            while '' in _ :
                _.remove('')
            if not _[-1].startswith('_') and _[-1]!='completed.0':
                var_data.append(_)
        return var_data
        
    def analyze_var(bytes_data, size, ENDIAN):
        """
            Analyses most significant byte to infer signed or unsigned values
            if most_sig_byte == 0b10000000, it is most probably signed

            NOTE :  It does not explicitly say if the data is signed or not, but is accurate and consistent with results. Doesnt work with large numbers
                    and some unsigned values using 'b10000000' in place of its most significant byte, and idk how to fix it :/
        """

        most_sig_byte = bytes_data[-1] if ENDIAN == 'little' else bytes_data[0]
        signed_guess = most_sig_byte & 0x80 != 0 #checks if the bytes_data is potentially negative

        if signed_guess:
            signed_value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=True)    
            unsigned_value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False)
            
            if signed_value <= 0:
                value = signed_value
            else:
                value = unsigned_value  # Treat as unsigned
        else:
            value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False)

        return value
    

    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        

        data_list = [] 
        for section in elf.iter_sections():
            sh_addr = section['sh_addr']
            sh_size = section['sh_size']

            for n in get_var_addr(filename):
                address = int(n[1], 16)
                size = int(n[2])
                name = n[-1]
                dump = {}
            # Check if address falls in this section
                if sh_addr <= address < sh_addr + sh_size:
                    offset = address - sh_addr
                    data = section.data()[offset:offset+size]
                    
                    dump['Variable Name'] = name
                    dump['Address'] = hex(address)
                    dump['Size'] = size
                    dump['Hex Dump'] = str_break(data.hex())
                    dump['ASCII Dump'] = str_break(data.decode(errors='ignore'))
                    dump['Decimal'] = str_break(str(int(data.hex(), 16)))

                    bytes_data = bytes.fromhex(data.hex())

                    if size == 8:
                        try:
                            value = struct.unpack(prefix + 'd', bytes_data)[0] # Double
                            if str(value) != 'nan':
                                dump['Double'] = value
                            value = analyze_var(bytes_data, size, ENDIAN) #int64
                            #value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False )
                            dump['int_64'] = value
                        except:
                            pass
                            
                    if size == 4:
                        try:
                            value = struct.unpack(prefix + 'f', bytes_data)[0]  # Float
                            if str(value) != 'nan':
                                dump['Float'] = value
                            value = analyze_var(bytes_data, size,  ENDIAN)  #int32
                            #value = int.from_bytes(bytes_data, byteorder=ENDIAN, signed=False )
                            dump['int32'] = value 
                        except:
                            pass
  
                    data_list.append(dump)

        return data_list
