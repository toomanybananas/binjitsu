<%
  from pwnlib.shellcraft import thumb
  from pwnlib.util import lists, packing
%>
<%page args="string, append_null = True, register = 'r7'"/>
<%docstring>
Pushes a string onto the stack without using
null bytes or newline characters.

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.

Examples:
    >>> print enhex(asm(shellcraft.pushstr('Hello\nWorld!', True)))
    87ea070780b4dff8047001e0726c642180b4dff8047001e06f0a576f80b4dff8047001e048656c6c80b4
    >>> print shellcraft.pushstr('abc')
        /* push 'abc\x00' */
        ldr r7, value_4
        b value_4_after
    value_4: .word 0xff636261
    value_4_after:
        lsl r7, #8
        lsr r7, #8
        push {r7}
    >>> print enhex(asm(shellcraft.pushstr('\x00', False)))
    87ea070780b4

</%docstring>
<%
    if append_null:
        string += '\x00'
    if not string:
        return

    offset = len(string)
    while offset % 4:
        offset += 1
%>\
    /* push ${repr(string)} */
% for word in lists.group(4, string, 'fill', '\x00')[::-1]:
    ${thumb.mov(register, packing.unpack(word))}
    push {${register}}
% endfor
