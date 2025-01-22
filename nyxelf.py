import json
import os
import argparse
import webview
from json2html import json2html

from src.constructor import body
from src.sandbox import session, ext_copy
from src.static_analysis import data
from src.trace_parser import parser, init_parser

def static_analysis(file_path, save_json, unpack):
    """
    Perform static analysis on the given file and generate an HTML report.

    Args:
        file_path (str): Path to the file to be analyzed.
        save_json (bool): Whether to save the analysis result as JSON.
        unpack (bool): Whether to attempt unpacking UPX.
    """
    analysis_result = data(file_path, unpack)
    analysis_json = json.dumps(analysis_result, indent=4)

    if save_json:
        with open('./data/static_analysis.json', 'w') as json_file:
            json_file.write(analysis_json)

    html_report = json2html.convert(json=analysis_json, escape=False)

    with open("frontend/static.html", 'w') as html_file:
        html_file.write(f'''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Static Analysis: {file_path}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" type="text/css" href="styles/static.css" />
  <link rel="icon" href="favicon.png">
</head>
<body>
  <h1>Static Analysis</h1>
   <div class = 'linkbox'>
  <a href='./disassm.html' class = 'link'>Disassembly</a>
  <a href='./dynamic.html' class = 'link'>Dynamic Analysis</a>
  </div>
  {html_report}
</body>
</html>
''')

def dynamic_analysis(file_path, max_length, trace_type, save_json, sandbox = 'sandbox'):
    """
    Perform dynamic analysis on the given file and generate an HTML report.

    Args:
        file_path (str): Path to the file to be analyzed.
        max_length (int): Maximum length of ASCII strings in strace output.
        trace_type (str): Type of trace output ("short" or "long").
        save_json (bool): Whether to save the analysis result as JSON.
    """
    ext_copy(file_path, f"{sandbox}/rootfs.ext2", "root/")  # Copy file to sandbox
    session(file_path, f'./{sandbox}/bzImage', f'./{sandbox}/rootfs.ext2', max_length)  # Start VM session

    with open('./data/strace.log', 'r') as log_file:
        parsed_data = init_parser(log_file)
        call_list = parser(parsed_data, trace_type)
        trace_json = json.dumps(call_list, indent=4)

        if save_json:
            with open('./data/dynamic_analysis.json', 'w') as json_file:
                json_file.write(trace_json)

        html_report = json2html.convert(json=trace_json, escape=False)

        with open("frontend/dynamic.html", 'w') as html_file:
            html_file.write(f'''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dynamic Analysis: {file_path}</title>
  <link rel="stylesheet" type="text/css" href="styles/static.css" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" href="favicon.png">
</head>
<body>
  <h1>Dynamic Analysis</h1>
  <div class = 'linkbox'>
  <a href='./static.html' class = 'link'>Static Analysis</a>
  <a href='./disassm.html' class = 'link'>Disassembly</a>
  </div> 
  {html_report}
</body>
</html>
''')

def disassemble(file):
    """
    Perform static analysis on the given file and generate an HTML report.

    Args:
        file_path (str): Path to the file to be analyzed.
        save_json (bool): Whether to save the analysis result as JSON.
        unpack (bool): Whether to attempt unpacking UPX.
    """

    with open("frontend/disassm.html", 'w') as html_file:
        html_file.write(f'''
<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/styles/atom-one-dark-reasonable.css">
<script src="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/highlight.min.js"></script>
<script src="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/languages/x86asm.min.js"></script>
<script>hljs.highlightAll();</script>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Disassembly</title>
  <link rel="stylesheet" type="text/css" href="styles/disassembly.css" /> <!-- Link your CSS file here -->
</head>
{body(file)}
</html>    
''')


def show_analysis_window(file_path, title):
    """
    Open a web view window to display the analysis report.

    Args:
        file_path (str): Path to the file analyzed.
        title (str): Title of the web view window.
    """
    webview.create_window(f'{title}: {file_path}', './frontend/static.html', maximized=True)
    webview.start()

def runner(file_path, max_length, title, trace_type, save_json, unpack):
    """
    Run both static and dynamic analysis and display the results.

    Args:
        file_path (str): Path to the file to be analyzed.
        max_length (int): Maximum length of ASCII strings in strace output.
        title (str): Title of the analysis.
        trace_type (str): Type of trace output ("short" or "long").
        save_json (bool): Whether to save the analysis result as JSON.
        unpack (bool): Whether to attempt unpacking UPX.
    """ 
    if os.path.exists(file_path):

        static_analysis(file_path, save_json, unpack)
        dynamic_analysis(file_path, max_length, trace_type, save_json)
        disassemble(file_path)
        show_analysis_window(file_path, title)
    else:
        print("[#] Critical Error : File Not Found")

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
            "Nyxelf simplifies static and dynamic analysis of ELF binaries,\n"
            "enabling you to extract valuable insights effortlessly.\n"
            "And can be used for vulnerability assessments, unpacking,\n"
            "syscall tracing, and memory analysis.\n\n"
            "Examples:\n"
            "  Analyze an ELF file statically and dynamically:\n"
            "    python3 nyxelf.py --file path/example.elf --json --unpack\n\n"
            "  Perform a detailed syscall trace with reduced verbosity:\n"
            "    python3 nyxelf.py --file path/example.elf --short --length 1024\n\n"
            "Happy analyzing!\n"
            "[&] https://github.com/m3rcurylake\n"
            "[&] By Ankit Mukherjee")

    parser.add_argument('--unpack', action='store_true', help='Attempt to unpack UPX file before analysis.')
    parser.add_argument('--json', action='store_true', help='Save JSON output of the analysis.')
    parser.add_argument('--file', type=str, required=True, help='Path to the file to be analyzed.')
    parser.add_argument('--short', action='store_true', help='Use short trace output (hides args and reduces verbosity).')
    parser.add_argument('--length', type=int, default=2048, help='Maximum length of ASCII strings in strace output.')

    args = parser.parse_args()

    trace_type = "short" if args.short else "long"

    runner(
        file_path=args.file,
        max_length=args.length,
        title="Nyxelf",
        trace_type=trace_type,
        save_json=args.json,
        unpack=args.unpack
    )

if __name__ == "__main__":
    main()
