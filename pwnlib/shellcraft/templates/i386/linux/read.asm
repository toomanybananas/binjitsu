<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<%page args="fd = 0, n = 0x400, buf = None"/>
<%docstring>Reads data from the specified file descriptor

Arguments:
    fd: File descriptor to read from
    buffer: File descriptor to write to
    n: Number of bytes to read
</%docstring>

<%
label  = common.label('getpc')
label2 = common.label('havepc')
%>

% if buf is None:
    call ${label}
    ${label2}:
    pop eax
    ${i386.linux.syscall('SYS_read',  fd, 'eax', n)}
    ${label}:
    jmp ${label2}
% else:
    ${i386.linux.syscall('SYS_read', fd, buf, n)}
% endif
