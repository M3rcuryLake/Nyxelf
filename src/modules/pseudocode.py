import tempfile
from typing import List

import angr
from angr.analyses import CFGFast, Decompiler
from angr.knowledge_plugins import Function

import warnings
warnings.filterwarnings('ignore')

def decompile(file_path):

    """
Decompile ELF binaries to C-like pseudocode using angr.

This script:
  • Loads the target ELF binary into an angr Project
  • Builds a fast control-flow graph (CFG) with CFGFast
  • Recovers calling conventions and local variables
  • Iterates over discovered non-PLT functions
  • Decompiles each into a C-like representation and prints it

Note:
  – Adapted for educational/hobby-based use from angr-based tooling (e.g. the
    approach used in Decompiler Explorer’s angr backend:
    https://github.com/decompiler-explorer/decompiler-explorer)
  – Provided as a demonstration of static decompilation with angr.
  – Not an official part of angr or Decompiler Explorer.
"""

    print('[*] Generating C-Language Pseudocode')

    with open(file_path, 'rb') as f:
        t = tempfile.NamedTemporaryFile()
        t.write(f.read())
        t.flush()

    p = angr.Project(t.name, auto_load_libs=False, load_debug_info=False)
    cfg = p.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
    )
    p.analyses.CompleteCallingConventions(
        cfg=cfg.model, recover_variables=True, analyze_callsites=True
    )

    funcs_to_decompile: List[Function] = [
        func
        for func in cfg.functions.values()
        if not func.is_plt and not func.is_simprocedure and not func.is_alignment
    ]
    output = ''
    for func in funcs_to_decompile:
        try:
            decompiler: Decompiler = p.analyses.Decompiler(func, cfg=cfg.model)

            if decompiler.codegen is None:
                print(f"[*] No decompilation output for function {func.name}\n")
                continue
            output += decompiler.codegen.text
        except Exception as e:
            print(f"[*] Exception thrown decompiling function {func.name}: {e}")

    print('[*] Generation of C-Language Pseudocode Completed')
    return output
