
# Nyxelf
![GitHub License](https://img.shields.io/github/license/m3rcurylake/nyxelf) ![GitHub Created At](https://img.shields.io/github/created-at/m3rcurylake/nyxelf) ![GitHub last commit](https://img.shields.io/github/last-commit/m3rcurylake/nyxelf) ![GitHub commit activity](https://img.shields.io/github/commit-activity/t/m3rcurylake/nyxelf) ![GitHub Issues](https://img.shields.io/github/issues/M3rcurylake/nyxelf) ![GitHub Repo stars](https://img.shields.io/github/stars/M3rcurylake/nyxelf)


Nyxelf is a powerful tool for analyzing malicious Linux ELF binaries, offering both **static** and **dynamic** analysis. It combines tools like `readelf`, `objdump`, and `pyelftools` for static analysis with a custom sandbox for dynamic analysis in a controlled environment using QEMU, a minimal Buildroot-generated image, and `strace`. With Nyxelf, you can gain deep insights into executable files, including unpacking, syscall tracing, and process/file activity monitoring, all presented through an intuitive GUI powered by `pywebview`. 

Json files and other logs are saved to `/data`, while the file-system and kernel image is saved to `/sandbox`.  


## System Dependencies:

**Install required packages**: Ensure you have python3 and python-pip installed and set to path and run the following commands, 

```bash
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager e2tools -y
git clone https://github.com/m3rcurylake/nyxelf.git
cd nyxelf && pip install -r requirements.txt
```

After everything is completely installed, you can run Nyxelf as following:

```bash
python3 nyxelf.py --help
```

## Features:

- **Static Analysis**:
  - Inspect ELF headers, sections, and symbols.
  - Decode assembly and variable data.
  - Analyze suspicious imports which can be related to anti-debugging.
  
- **Dynamic Analysis**:
  - Run binaries in a secure QEMU-based sandbox.
  - Record process activity, syscalls, and file interactions with `strace`.
  - Supports custom verbosity for syscall tracing.

- **Other Features**:
  -  Optional automatic UPX unpacking.
  - JSON output for automated workflows.
  - Adjustable syscall trace verbosity and string length filtering.


## Usage
```
>> python3 Nyxelf.py [-h] [--unpack] [--json] --file FILE [--short] [--length LENGTH]

 _____  ___    ___  ___   ___  ___    _______   ___         _______
("   \|"  \  |"  \/"  | |"  \/"  |  /"     "| |"  |       /"     "|
|.\\   \    |  \   \  /   \   \  /  (: ______) ||  |      (: ______)
|: \.   \\  |   \\  \/     \\  \/    \/    |   |:  |       \/    |
|.  \    \. |   /   /      /\.  \    // ___)_   \  |___    // ___)
|    \    \ |  /   /      /  \   \  (:      "| ( \_|:  \  (:  (
 \___|\____\) |___/      |___/\___|  \_______)  \_______)  \__/

            [Another ELF Analysis Framework]

options:
  -h, --help       show this help message and exit
  --unpack         Attempt to unpack UPX file before analysis.
  --json           Save JSON output of the analysis.
  --file FILE      Path to the file to be analyzed.
  --short          Use short trace output (hides args and reduces verbosity).
  --length LENGTH  Maximum length of ASCII strings in strace output.

Nyxelf simplifies static and dynamic analysis of ELF binaries,
enabling you to extract valuable insights effortlessly.
And can be used for vulnerability assessments, unpacking,
syscall tracing, and memory analysis.

Examples:
  Analyze an ELF file statically and dynamically:
    python3 nyxelf.py --file path/example.elf --json --unpack

  Perform a detailed syscall trace with reduced verbosity:
    python3 nyxelf.py --file path/example.elf --short --length 1024

Happy analyzing!
[&] https://github.com/m3rcurylake
[&] By Ankit Mukherjee
```


### File Structure
```
.
├── data
├── frontend
│   ├── assets
│   │   ├── BebasNeue-Regular.ttf
│   │   └── Nunito-Regular.ttf
│   └── styles
│       └── static.css
├── nyxelf.py
├── README.md
├── requirements.txt
├── sandbox
│   ├── bzImage
│   └── rootfs.ext2
└── src
    ├── __init__.py
    ├── modules
    │   ├── anti_debug_apis.py
    │   ├── __init__.py
    │   ├── __main__.py
    │   ├── packer_detection.py
    │   ├── section_entropy.py
    │   └── variables.py
    ├── sandbox.py
    ├── static_analysis.py
    └── trace_parser.py
```

## Roadmap

- Decompiler and Disassembler Support
- Network Analysis
- Better UI and Optimisation
- Anti anti-debugging for ptrace etc.
- Disassemble Pyinstaller files
- Add Effective Logging

