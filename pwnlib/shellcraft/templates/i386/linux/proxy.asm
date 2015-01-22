<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<%page args="fd_a, fd_b, n"/>
<%docstring>
Proxies data between two file descriptors by forking and shuttling
data around.

Arguments:
    fd_read: File descriptor to read from
    fd_write: File descriptor to write to
    n: Number of bytes to read
</%docstring>
<%

    size_round = n + (n % 0x20)
%>

${i386.mov()}
${i386.linux.syscall('SYS_fork')}
cmp eax, 0
jz ${parent}

${i386.linux.syscall('SYS_read',  'ebp', 'esp', n)}
${i386.linux.syscall('SYS_write', fd_b, 'esp', n)}

${i386.linux.syscall('SYS_read',  fd_b, 'esp', n)}
${i386.linux.syscall('SYS_write', fd_a, 'esp', n)}



${i386.mov('eax', size_round)}
add esp, eax
-