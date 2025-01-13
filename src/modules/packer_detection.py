import subprocess
import math

def detect_packer(filename, use_unpacked):
        result = subprocess.run(['strings', filename], capture_output=True, text=True)
        strings = result.stdout.split(" ")

        # List of common packer markers
        packers = {
            "UPX": ["UPX", "UPX!", "UPX0", "UPX1", "UPX2"],
            "MPRESS": ["MPRESS1", "MPRESS2"],
            "ASPack": ["ASPack"],
            "Themida": ["Themida"],
            "PECompact": ["PEC2"],
            "FSG": ["FSG!"],
            "MEW": ["MEW"],
            "EXEcryptor": ["EXEcryptor"]
        }

        found = []
        for packer, hex in packers.items():
            if any(item in strings for item in hex):
                found.append(packer)

        def calculate_entropy(data):
            # Initialize a list to count byte frequencies (256 possible byte values)
            byte_frequencies = [0] * 256
            total_bytes = len(data)

            for byte in data:
                byte_frequencies[byte] += 1

            # Shannon entropy calc:
            entropy = 0
            for count in byte_frequencies:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)

            return entropy

        if use_unpacked == "y":
            note = "Working with Unpacked file"
        else :
            note = "Working with packed file"



        with open(filename, 'rb') as file:
            data = file.read()
        fileentropy = calculate_entropy(data)


        if len(found) > 0:
            print(f"{filename} is packed with {', '.join(found)}, Entropy: {fileentropy:.4f}")
            pa_ = f"{filename} is packed with {', '.join(found)}"

            if 'UPX' in found and use_unpacked :
                #TODO : Fix error handling for UPX files with manipulated hex data 
                try:
                    subprocess.run(["upx", "-d", filename], check=True, stdout=subprocess.DEVNULL)
                    print("[*] Unpacked UPX file successfully")

                except:
                    print("[*] Cound not Unpack UPX file")
        else :
            if fileentropy > 6:
                pa_ = "High Entropy detected: Possible encryption or packed sections detected."
            else:
                pa_ = f"{filename} is not packed with any packer"
                
                

        return {"Packer Present" : pa_, "Entropy" : fileentropy, "Note" : note}
    


#detect_packer('../test_bin/datatypes')

