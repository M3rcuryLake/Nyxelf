
from src.modules.pseudocode import construct_gen
from src.modules.decompile import disassemble_elf

def body(file):
    asm = disassemble_elf(file)
    c = construct_gen(file)
    body = f'''<body>
  <h1>Disassembly</h1>
  <div class = 'linkbox'>
  <a href='./static.html' class = 'link'>Static Analysis</a>
  <a href='./dynamic.html' class = 'link'>Dynamic Analysis</a>
  </div>

  <div class = "sudo" >
  <div class="container">
    <div class="column">
      <h2>Assembly Dump</h2>
          <pre>
      <code class = 'language-x86asm'>
{asm}
      </code>
      </pre>
    </div>
    <div class="column">
      <h2>Decompiled Pseudocode</h2>
          <pre>
      <code class = 'language-c' >
{c}
      </code>
      </pre>
    </div>
  </div>
</body>'''
    return body 
