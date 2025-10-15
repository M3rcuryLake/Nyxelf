import subprocess

def detect_pyinstaller(filename):
        with open(filename, 'rb') as f:
            data = f.read()
        # PyInstaller markers
        markers = [
            b'pyiboot01_bootstrap',
            b'pyimod',
            b'PYZ-00',
            b'_MEIPASS'
        ]

        for marker in markers:
            if marker in data:
                print(f"[*] Detected PyInstaller marker: {marker.decode('utf-8', 'ignore')}")
                return f"Detected PyInstaller marker: {marker.decode('utf-8', 'ignore')}"
            else:
                return False


def detect_packer(filename, use_unpacked):
        pa_ = ''
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

        if use_unpacked:
            note = "Working with Unpacked file"
        if len(found)>1 :
            note = "Working with packed file"
        else :
        	note = "No Packer Found"



        if len(found) > 0:
            pa_ = f"{filename} is packed with {', '.join(found)}"

            if 'UPX' in found and use_unpacked :
                print("[*] Trying to unpack UPX Compressed binary ")
                #TODO : Fix error handling for UPX files with manipulated hex data 
                try:
                    subprocess.run(["upx", "-d", filename], check=True, stdout=subprocess.DEVNULL)
                    print("[*] Unpacked UPX file successfully")

                except:
                    print("[*] Cound not Unpack UPX file")

        pyInst = detect_pyinstaller(filename)
        if pyInst:
            pa_ = pyInst


        if pa_ == '':
            pa_ = 'None'    
                
        return {"Packer" : pa_, "Note" : note}
    


