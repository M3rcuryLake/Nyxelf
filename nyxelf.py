import os
import html
import argparse
import webview
from string import Template

from src.modules.ai_overview import genai_transcript
from src.modules.disassemble import disassemble
from src.modules.pseudocode import decompile
from src.sandbox import session, ext_copy
from src.static_analysis import data
from src.pcap_parser import read_pcap

def static_analysis(file_path, unpack):
    """
    Perform static analysis on the given file and generate an HTML report.

    Args:
        file_path (str): Path to the file to be analyzed.
        unpack (bool): Whether to attempt unpacking UPX.
    """
    analysis_result = data(file_path, unpack)

    with open("./frontend/templates/static.html", 'r') as html_file:
        html_template = html_file.read()
        fi_table, header_table, symbol_table, dynsym_table, function_table, section_table, variable_table = analysis_result
        html_static = Template(html_template).substitute(
    fi_table=fi_table,
    header_table=header_table,
    symbol_table=symbol_table,
    dynsym_table=dynsym_table,
    function_table=function_table,
    section_table=section_table,
    variable_table=variable_table
)

    with open("./frontend/static.html", 'w') as static:
        static.write(html_static)

def dynamic_analysis(file_path, aio, trace_type, nettrace, logtofile, sandbox = 'sandbox'):
    """
    Perform dynamic analysis on the given file and generate an HTML report.

    Args:
        file_path (str): Path to the file to be analyzed.
        aio (bool) : Generative AI based Overviews.
        trace_type (str): Type of trace output.
    """
    ext_copy(file_path, f"{sandbox}/rootfs.ext2", "root/")
    ext_copy(f"tracers/{trace_type}", f"{sandbox}/rootfs.ext2", "root/")

    dynamic_log, mem_log, sandbox_time, exec_time, size = session(file_path, f'./{sandbox}/bzImage', f'./{sandbox}/rootfs.ext2', trace_type, nettrace, logtofile)
    if nettrace:
        network_activity = read_pcap("./data/trace.pcap")
    else :
        network_activity = "None"
    
    if aio:
        ai_trans = genai_transcript(dynamic_log)
        if ai_trans is not None :
            print("[*] Response successfully generated.")
    else :
        ai_trans = "Generative AI Based Overviews are not enabled, run again with required positional arguments to get AI Transcripts..."

    with open("./frontend/templates/dyn.html", 'r') as html_file:
        html_template = html_file.read() 
        html_dyn = Template(html_template).substitute(
    dynamic_log = dynamic_log,
    network_activity = network_activity,
    mem_log = mem_log,
    sandbox_time = sandbox_time,
    exec_time = exec_time,
    ai_transcript = ai_trans,
    size = size
)

    with open("frontend/dyn.html", 'w') as html_file:
        html_file.write(html_dyn)

def complete_disas(file):
    """
    Deconstructs and produces both assembly and C like pseudocode.
    Args:
        file (str) : Path to the file analyzed. 
    """

    with open("frontend/templates/dump.html") as html_file:
        html_template = html_file.read() 
        assem, symbols, functions  = disassemble(file)
        clang = html.escape(decompile(file))
        html_dump = Template(html_template).substitute(
    asm = html.escape(assem),
    symbols = symbols,
    functions = functions,
    cpseudo = clang
)

    with open("frontend/dump.html", 'w') as html_file:
        html_file.write(html_dump)


def show_analysis_window(file_path, title):
    """
    Open a web view window to display the analysis report.

    Args:
        file_path (str): Path to the file analyzed.
        title (str): Title of the web view window.
    """
    webview.create_window(f'{title}: {file_path}', './frontend/static.html', maximized=True, text_select=True)
    webview.start()

def runner(file_path, title, aio, trace_type, nettrace, logtofile, unpack):
    """
    Run both static and dynamic analysis and display the results.

    Args:
        file_path (str): Path to the file to be analyzed.
        title (str): Title of the analysis.
        trace_type (str): Type of trace output.
        aio (bool): Whether to provide AI based overview.
        unpack (bool): Whether to attempt unpacking UPX.
    """ 
    if os.path.exists(file_path):

        static_analysis(file_path, unpack)
        dynamic_analysis(file_path, aio, trace_type, nettrace, logtofile)
        complete_disas(file_path)
        show_analysis_window(file_path, title)
    else:
        print("[*] Critical Error : File Not Found")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        prog="Nyxelf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=r'''
 _____  ___    ___  ___   ___  ___    _______   ___         _______  
("   \|"  \  |"  \/"  | |"  \/"  |  /"     "| |"  |       /"     "| 
|.\\   \    |  \   \  /   \   \  /  (: ______) ||  |      (: ______) 
|: \.   \\  |   \\  \/     \\  \/    \/    |   |:  |       \/    |   
|.  \    \. |   /   /      /\.  \    // ___)_   \  |___    // ___)   
|    \    \ |  /   /      /  \   \  (:      "| ( \_|:  \  (:  (      
 \___|\____\) |___/      |___/\___|  \_______)  \_______)  \__/      

                [Another ELF Analysis Framework]
''',
            epilog=
            "Nyxelf is an unpredictable yet powerful \"cutter\" which\n"
            "simplifies static and dynamic analysis of ELF binaries,\n"
            "enabling you to extract valuable insights effortlessly.\n\n"
            "Examples:\n"
            "  Analyze an ELF file statically and dynamically:\n"
            "    python3 nyxelf.py --file path/example --unpack\n\n"
            "  Kernel and Network-level analysis with AI-assisted summarization for dynamic analysis:\n"
            "    python3 nyxelf.py --file path/example --genai --kernel --nettrace\n\n"
            "Happy analyzing!\n"
            "[&] https://github.com/m3rcurylake\n"
            "[&] By Ankit Mukherjee\n\n")

    parser.add_argument('--file', type=str, required=True, help='Path to the file to be analyzed.')
    parser.add_argument('--unpack', action='store_true', help='Attempt to unpack UPX-compressed binaries before analysis.')
    parser.add_argument('--genai', action='store_true', help='Invoke AI-assisted summarization for dynamic analysis.')
    parser.add_argument('--nettrace', action='store_true', help='Trace network activity using tcpdump during execution.')
    parser.add_argument('--syscall', action='store_true', help='List only syscall hits (suppress argument details).')
    parser.add_argument('--kernel', action='store_true', help='Show kernel tracepoints probed during execution.')
    parser.add_argument('--logtofile', action='store_true', help='Saves QEMU Logs to `qemu.logs` under ./data/, else prints to stdout.')

    args = parser.parse_args()

    trace_type = ''
    if args.syscall :
        trace_type = "syscall.sh"
    if args.kernel :
        trace_type = "kernel.sh"
    else:
        trace_type = "default.sh"

    runner(
        file_path=args.file,
        title="Nyxelf",
        aio = args.genai,
        trace_type=trace_type,
        nettrace=args.nettrace,
        logtofile=args.logtofile,
        unpack=args.unpack
    )

if __name__ == "__main__":
    main()
