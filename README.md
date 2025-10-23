
# Nyxelf
  
![Static Badge](https://img.shields.io/badge/made_by-m3rcurylake-orange?style=for-the-badge) ![GitHub License](https://img.shields.io/github/license/m3rcurylake/nyxelf?style=for-the-badge) ![GitHub Created At](https://img.shields.io/github/created-at/m3rcurylake/nyxelf?style=for-the-badge) ![GitHub last commit](https://img.shields.io/github/last-commit/m3rcurylake/nyxelf?style=for-the-badge) ![GitHub commit activity](https://img.shields.io/github/commit-activity/t/m3rcurylake/nyxelf?style=for-the-badge) ![GitHub Issues](https://img.shields.io/github/issues/M3rcurylake/nyxelf?style=for-the-badge)  ![GitHub Repo stars](https://img.shields.io/github/stars/M3rcurylake/nyxelf)

<table>
<tr>
<td>
<div align='center'>
  
### _About_
  
Nyxelf is a powerful tool for analyzing malicious Linux ELF binaries, offering both **static** and **dynamic** analysis. It combines tools like `readelf`, `objdump`, and `pyelftools` for static analysis with a custom sandbox for dynamic analysis in a controlled environment using QEMU, a minimal Buildroot-generated image,  and a combination of `valgrind`, `tcpdump` and `bpftrace` which is further enhanced by integrated AI-assisted summarization. Also it decompiles binary data to Assembly and C like pseudocode using `capstone`, `angr` and `radare2`. With Nyxelf, you can gain deep insights into executable files, including unpacking, syscall tracing, network, memory and process/file activity monitoring, all presented through an intuitive GUI powered by `pywebview`. 

</div>
</table>
</tr>
</td> 


### _A simple working demo_ :

![Usage](https://github.com/M3rcuryLake/Nyxelf/blob/main/nyxelf-demo.gif)

## Features:

- **Static Analysis**:
  - Inspect ELF headers, sections, and symbols.
  - Decode assembly and variable data.
  - Analyze suspicious imports which can be related to anti-debugging.
  
- **Dynamic Analysis**:
  - Run binaries in a secure QEMU-based sandbox.
  - Memory and Network analysis with `valgrind` and `tcpdump`.
  - Record process activity, syscalls, and file interactions with `bpftrace`.
  - Supports custom verbosity and `bpf` scripts for syscall and kernal tracing.
  - Generative AI based overview powered by g4f.
 
- **Decompilation**:
  - Decompiles binary to Assembly and C like pseudocode using `capstone`, `r2pipe` and `angr`.
  - Tries to retrive variable data from `.rodata` and `.data` sections.

- **Other Features**:
  -  Optional automatic UPX unpacking.
  - Cooler Contrastive theme based around One-Dark and Binary Ninja.
  - Adjustable syscall trace verbosity and string length filtering.
  - Option to either log to file or print to stdout.
  - Uses `highlightjs`  CDNs for syntax highlighting.


> [!NOTE]
> `pcap` files and other qemu logs are saved to `/data`, while the kernel and compressed filesystem image is saved to `/sandbox`.  


## System Dependencies:

**Install required packages**: Ensure you have python3 and python-pip installed and set to path and run the following commands, 

```bash
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager e2tools p7zip -y
git clone https://github.com/m3rcurylake/nyxelf.git
cd nyxelf && pip install -r requirements.txt
p7zip sandbox/rootfs.ext2.7z
```
After everything is completely installed, you can run Nyxelf as following:

```bash
python3 nyxelf.py --help
```

## *Want to build the images yourself?*
I documented every hurdle and solution I encountered while compiling the kernel, including each modification made when a build failed. The build process alone took more than twenty hours in total, with repeated compilation and troubleshooting. This section is dedicated to nearly a week of intensive research, including browsing Buildroot's historical Git commits. For detailed instructions on compiling the custom Buildroot kernel and root filesystem used for sandbox analysis, make yourself a strong coffee and see the [BUILDROOT.md](https://github.com/M3rcuryLake/Nyxelf/blob/main/BUILDROOT.md).
The [configuration file](https://github.com/M3rcuryLake/Nyxelf/blob/main/data/.config) for the buildroot is saved under the `data` directory as `.config`


## Usage

To start analysing binaries, refer to the following help menu, or move to the project directory and type `python nyxelf.py --file FILE` in the terminal for a quick start, where `FILE` is the target binary. The output will be displayed in a new pywebview GUI window.

```
usage: Nyxelf [-h] --file FILE [--unpack] [--genai] [--nettrace] [--syscall] [--kernel] [--logtofile]

 _____  ___    ___  ___   ___  ___    _______   ___         _______
("   \|"  \  |"  \/"  | |"  \/"  |  /"     "| |"  |       /"     "|
|.\\   \    |  \   \  /   \   \  /  (: ______) ||  |      (: ______)
|: \.   \\  |   \\  \/     \\  \/    \/    |   |:  |       \/    |
|.  \    \. |   /   /      /\.  \    // ___)_   \  |___    // ___)
|    \    \ |  /   /      /  \   \  (:      "| ( \_|:  \  (:  (
 \___|\____\) |___/      |___/\___|  \_______)  \_______)  \__/

                [Another ELF Analysis Framework]

options:
  -h, --help   show this help message and exit
  --file FILE  Path to the file to be analyzed.
  --unpack     Attempt to unpack UPX-compressed binaries before analysis.
  --genai      Invoke AI-assisted summarization for dynamic analysis.
  --nettrace   Trace network activity using tcpdump during execution.
  --syscall    List only syscall hits (suppress argument details).
  --kernel     Show kernel tracepoints probed during execution.
  --logtofile  Saves QEMU Logs to `qemu.logs` under ./data/, else prints to stdout.

Nyxelf is an unpredictable yet powerful "cutter" which
simplifies static and dynamic analysis of ELF binaries,
enabling you to extract valuable insights effortlessly.

Examples:
  Analyze an ELF file statically and dynamically and save the logs:
    python3 nyxelf.py --file path/example --unpack --logtofile

  Kernel and Network-level analysis with AI-assisted summarization for dynamic analysis:
    python3 nyxelf.py --file path/example --genai --kernel --nettrace

Happy analyzing!
[&] https://github.com/m3rcurylake
[&] By Ankit Mukherjee
```


### File Structure
```
Nyxelf
├── BUILDROOT.md
├── LICENSE
├── README.md
├── data
│   └──.config
├── frontend
│   ├── package.json
│   ├── src
│   │   └── input.css
│   ├── style
│   │   ├── atom-one-dark-reasonable.css
│   │   ├── highlight.min.js
│   │   ├── style.css
│   │   └── x86asm.min.js
│   └── templates
│       ├── dump.html
│       ├── dyn.html
│       └── static.html
├── nyxelf.py
├── requirements.txt
├── sandbox
│   ├── bzImage
│   └── rootfs.ext2.7z
├── src
│   ├── __init__.py
│   ├── modules
│   │   ├── __init__.py
│   │   ├── __main__.py
│   │   ├── ai_overview.py
│   │   ├── anti_debug_apis.py
│   │   ├── disassemble.py
│   │   ├── packer_detection.py
│   │   ├── pseudocode.py
│   │   └── variables.py
│   ├── pcap_parser.py
│   ├── sandbox.py
│   └── static_analysis.py
└── tracers
    ├── default.sh
    ├── kernel.sh
    └── syscall.sh
```

## Roadmap

- [x] Decompiler and Disassembler Support
- [x] Network Analysis
- [x] Better UI and Optimisation
- [ ] Anti anti-debugging for ptrace etc.
- [x] Detect Pyinstaller files
- [ ] Add Effective Logging

## Known Issues and Contribution.
_**TCPdump Dropping `ICMP`, `ARP` etc**_ : tcpdump running inside the guest shows no ICMP and ARP packets even when programs like `ping` or `traceroute` are run, forming PCAP files lacking reliable information. This may be caused by the choice of the networking. According to research, the current `qemu` command doesn’t actually define any explicit network backend, which means `qemu` silently defaults to:

  ```
    -netdev user,id=net0 \
    -device e1000,netdev=net0
  ```

That’s user-mode networking (NATed), and it only forwards TCP/UDP connections, fakes DNS and DHCP, and drops raw protocols like ICMP or ARP.
A fix for this would be using TAP or SLiRP with packet passthrough as TAP provides a real Layer-2 interface that behaves like a proper NIC, which helps in capturing the network and application layer activity.

_**Stdin Deadlock in Sandbox**_ : Binaries that use reads from the TTY or otherwise expect a TTY-based interactive stdin, the process appears to hang, crash, exit with EOF/SIGSEGV or enters a deadlock when ran under the sandboxed environment with tracing tools. This may happen due to `bpftrace` waiting for a stdin input and `pexpect` getting a wrong read like `"Enter a number :"` instead of `# ` therefore. A proper fix to this would be to add an option to support secondary inputs, though you can overcome this with a bit of shell magic or using some sort of wrapper, it would add unwanted noise in the bpftrace output and anyways, anyone would want maximum support. So letting reverse engineers to make the most out of it by adding the option to supply the binary with custom inputs or random gibberish, or letting them choose which signal (`SIGTERM`, `SIGKILL`, etc) they want to send to the running process after analysis ran for a certain timeframe, would be the way to go.

## License
This project is licensed under the [MIT](https://choosealicense.com/licenses/mit/) License - see the [LICENSE.md](https://github.com/m3rcurylake/nyxelf/LICENSE.md) file for details.
