<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.shellcraft import common %>
<%page args="sock = 'ebp', fd = 3"/>
<%docstring>
Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  dup       = common.label("dup")
  looplabel = common.label("loop")
%>

${dup}:
    ${i386.mov('ebx', sock)}
    ${i386.mov('ecx', fd)}
${looplabel}:
    dec ecx

    ${i386.linux.syscall('SYS_dup2', 'ebx', 'ecx')}
    jnz ${looplabel}
