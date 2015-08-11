<%
from pwnlib.shellcraft import pretty, value, common, registers
from pwnlib.shellcraft.i386 import mov, pushstr, setregs
from pwnlib import constants
%>
<%docstring>
Copies a string

Example:

    >>> sc  = 'jmp get_str\n'
    >>> sc += 'pop_str: pop eax\n'
    >>> sc += shellcraft.i386.strcpy('esp', 'eax')
    >>> sc += shellcraft.i386.linux.write(1, 'esp', 32)
    >>> sc += shellcraft.i386.linux.exit(0)
    >>> sc += 'get_str: call pop_str\n'
    >>> sc += '.asciz "Hello, world\\n"'
    >>> run_assembly(sc).recvline()
    'Hello, world\n'
</%docstring>
<%page args="dst, src"/>
    ${setregs({'ecx': -1,
               'edi': src,
               'esi': dst,
               'eax': 0})}
    push edi
    repnz scas al, BYTE PTR [edi]
    pop edi
    xchg edi, esi
    inc ecx
    neg ecx
    rep movs BYTE PTR [edi], BYTE PTR [esi]
