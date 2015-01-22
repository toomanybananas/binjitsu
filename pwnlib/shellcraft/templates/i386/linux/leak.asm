<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<%page args="fd"/>
<%docstring>Reads data from the specified file descriptor

Arguments:
    fd: File descriptor to read from
</%docstring>
<%
lab = common.label('lab')
%>

    push 0
${lab}:
    ${i386.linux.syscall('SYS_read',  fd, 'esp', 4)}
    pop eax
    mov ebx, [eax]
    push ebx
    ${i386.linux.syscall('SYS_write', fd, 'esp', 4)}
jmp ${lab}