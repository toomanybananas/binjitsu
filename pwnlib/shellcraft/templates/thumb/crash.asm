<% from pwnlib.shellcraft.thumb import mov %>
<%docstring>
Crash.

Example:

    >>> run_assembly(shellcraft.crash()).poll(True)
    -11
</%docstring>
    pop {r0-r12,lr}
    ldr sp, [sp, 64]
    bx  r1
