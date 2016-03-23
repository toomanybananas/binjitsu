import os
import random
import re
import shlex
import tempfile

from . import atexit
from . import elf
from . import tubes
from .asm import make_elf, make_elf_from_assembly, _bfdname
from .context import context, LocalContext
from .log import getLogger
from .util import misc
from .util import proc
from .qemu import get_qemu_user

log = getLogger(__name__)

@LocalContext
def debug_assembly(asm, execute=None, vma=None):
    """
    Creates an ELF file, and launches it with GDB.

    This is identical to debug_shellcode, except that
    any defined symbols are available in GDB, and it
    saves you the explicit call to asm().
    """
    tmp_elf = make_elf_from_assembly(asm, vma=vma, extract=False)
    os.chmod(tmp_elf, 0777)
    atexit.register(lambda: os.unlink(tmp_elf))
    return debug(tmp_elf, execute=execute, arch=context.arch)

@LocalContext
def debug_shellcode(data, execute=None, vma=None):
    """
    Creates an ELF file, and launches it with GDB.

    Arguments:
        data(str): Assembled shellcode bytes
        kwargs(dict): Arguments passed to context (e.g. arch='arm')

    Returns:
        A ``process`` tube connected to the shellcode on stdin/stdout/stderr.
    """
    if isinstance(data, unicode):
        log.error("Shellcode is cannot be unicode.  Did you mean debug_assembly?")
    tmp_elf = make_elf(data, extract=False, vma=vma)
    os.chmod(tmp_elf, 0777)
    atexit.register(lambda: os.unlink(tmp_elf))
    return debug(tmp_elf, execute=execute, arch=context.arch)

@LocalContext
def debug(args, execute=None, exe=None, ssh=None, env=None, local=False):
    """debug(args) -> tube

    Launch a GDB server with the specified command line,
    and launches GDB to attach to it.

    Arguments:
        args(str,list): Same args as passed to pwnlib.tubes.process
        execute(str): Script to execute when GDB is launched.
        exe(str): Path to the executable to launch (e.g. if argv0 is something else)
        env(dict): Set the environment of the launched process
        ssh(pwnlib.tubes.ssh.ssh): Remote ssh session to use to launch the process.
          Automatically sets up port forwarding so that gdb runs locally.
          Requires ``gdbserver`` to be installed on the target machine, or in the
          working directory.
        local(bool): If ``ssh`` is provided, use the local gdb instead of
          the one on the remote machine.  This will be much slower, since instead of
          just the GDB's text output, all of the process memory must go over the
          network.

    Returns:
        A tube connected to the target process
    """

    #
    # If the user has disabled debugging for this execution, don't attach the debugger.
    #
    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return tubes.process.process(args, executable=exe, env=env)

    #
    # If the process is already running, the user has used the wrong API.
    #
    if isinstance(args, (int, tubes.process.process, tubes.ssh.ssh_channel)):
        log.error("Use gdb.attach() to debug a running process")

    #
    # If a single command was provided, turn it into argv.
    #
    if isinstance(args, (str, unicode)):
        args = [args]

    #
    # Since we are going to modify the command line by prepending gdbserver
    # and arguments to it, we should save off a copy.
    #
    orig_args = list(args)

    #
    # If the user provided an SSH session, we need to spawn the process on the remote system.
    #
    if ssh:
        runner  = ssh.process
        which   = ssh.which
    else:
        runner  = tubes.process.process
        which   = misc.which

    #
    # If we are cross-debugging, we invoke qemu-user directly rather than letting
    # the binfmt_misc do it automatically.  This allows us to set the `-g` flag to
    # start QEMU's internal GDB server.
    #
    # Otherwise, just spin up gdbserver.
    #
    if ssh or context.native:
        gdbserver = which('gdbserver')

        if not gdbserver:
            log.error("gdbserver is not installed")

        args = [gdbserver]

        if context.aslr:
            args += ['--no-disable-randomization']

        args += ['localhost:0', '--']
        args += orig_args
    else:
        qemu_port = random.randint(1024, 65535)
        args = [get_qemu_user(), '-g', str(qemu_port), '--'] + args

    #
    # Make sure gdbserver (or qemu-XXX) exist on the target machine.
    #
    if not which(args[0]):
        message = "%s is not installed" % args[0]

        if ssh:
            message = "%s (on %s)" % (message, message.host)

        log.error(message)

    #
    # Ideally we know the full path to the binary.
    #
    if not exe:
        exe = which(orig_args[0])

    #
    # Spawn gdbserver (or QEMU) on the target machine.
    #
    gdbserver = runner(args, executable=exe, env=env)

    #
    # Grab the port the debugger is listening on, and the PID of the child.
    #
    if ssh or context.native:
        # Process /bin/bash created; pid = 14366
        # Listening on port 34816
        pattern = r'Process (?P<exe>.+) created; pid = (?P<pid>.+)\n'
        string  = gdbserver.recvline()
        match   = re.search(pattern, string)
        gdbserver.pid   = int(match.group('pid'))
        gdbserver.executable = int(match.group('exe'))

        pattern = r'Listening on port (?P<port>\d+)'
        string  = gdbserver.recvline()
        match   = re.search(pattern, string)

        port = int(match.group('port'))
    else:
        port = qemu_port

    listener = remote = None

    #
    # If the target is running on a remote system, we need to proxy some data.
    #
    if ssh:
        #
        # Both gdb and gdbserver are running on the remote server
        # We need to proxy the gdb text input/output.
        #
        # The manner in which we do this underneath is to spawn a new, external
        # instance of SSH, which launches GDB on the remote server with the
        # correct arguments (see gdb.attach implementation for more info).
        #
        if not local:
            remote   = ssh.remote('127.0.0.1', port)
            listener = tubes.listen.listen()
            port     = listener.lport

        #
        # gdb runs locally, gdbserver runs on the remote server
        # We need to proxy gdb's remote debugging protocol.
        #
        # We just launch GDB locally and use 'target remote FOO' after setting
        # up the proxy channel.
        #
        else:
            remote   = ssh.remote('127.0.0.1', port)

    #
    # Now we simply "attach" to gdbserver / qemu listening port on localhost
    # (which is just proxied if ssh is used.)
    #
    attach(('127.0.0.1', port),
           exe=exe,
           execute=execute,
           need_ptrace_scope = False,
           remote_gdbserver = local)

    #
    # Actually proxy the data after the connection arrives, if ssh is being used.
    #
    if ssh:
        remote <> listener.wait_for_connection()

        # Disable showing GDB traffic when debugging verbosity is increased
        remote.level = 'error'
        listener.level = 'error'

    #
    # gdbserver outputs a message when a client connects, which we don't want
    # the user to see.
    #
    # Consume that line if it looks like what we expect.
    #
    garbage = gdbserver.recvline(timeout=1)

    if "Remote debugging from host" not in garbage:
        gdbserver.unrecv(garbage)

    return gdbserver

def get_gdb_arch():
    return {
        'amd64': 'i386:x86-64',
        'powerpc': 'powerpc:common',
        'powerpc64': 'powerpc:common64',
        'mips64': 'mips:isa64',
        'thumb': 'arm'
    }.get(context.arch, context.arch)


@LocalContext
def attach(target, execute = None, exe = None, need_ptrace_scope = True, remote_gdbserver =None):
    """attach(target, execute = None, exe = None, arch = None) -> None

    Start GDB in a new terminal and attach to `target`.
    :func:`pwnlib.util.proc.pidof` is used to find the PID of `target` except
    when `target` is a ``(host, port)``-pair.  In that case `target` is assumed
    to be a GDB server.

    If it is running locally and `exe` is not given we will try to find the path
    of the target binary from parsing the command line of the program running
    the GDB server (e.g. qemu or gdbserver).  Notice that if the PID is known
    (when `target` is not a GDB server) `exe` will be read from
    ``/proc/<pid>/exe``.

    If `gdb-multiarch` is installed we use that or 'gdb' otherwise.

    Arguments:
      target: The target to attach to.
      execute (str or file): GDB script to run after attaching.
      exe (str): The path of the target binary.
      arch (str): Architechture of the target binary.  If `exe` known GDB will
      detect the architechture automatically (if it is supported).

    Returns:
      :const:`None`
    """

    #
    # If the user has disabled debugging for this execution, don't attach the debugger.
    #
    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return tubes.process.process(args, executable=exe, env=env)

    #
    # If execute is a file object, then read it; we probably need to run some
    # more gdb script anyway.
    #
    if execute and isinstance(execute, file):
        with execute as fd:
            execute = fd.read()

    #
    # There must be a newline at the end of the script, or the last command will
    # not be executed.
    #
    if execute and not execute.endswith('\n'):
        execute += '\n'

    #
    # Prepare our own GDB script to run before the user's `execute` script.
    pre = ''

    #
    # If we are cross-debugging, the user must have installed a cross-debugging-aware
    # GDB, and we must inform GDB what architecture to expect, because QEMU is stupid.
    #
    if not context.native:
        if not misc.which('gdb-multiarch'):
            log.warn_once('Cross-architecture debugging usually requires gdb-multiarch\n' \
                '$ apt-get install gdb-multiarch')
        pre += 'set endian %s\n' % context.endian
        pre += 'set architecture %s\n' % get_gdb_arch()
        # pre += 'set gnutarget ' + _bfdname() + '\n'

    #
    # If ptrace_scope is set and we're not root, we cannot attach to a
    # running process.
    #
    # We assume that we do not need this to be set if we are debugging on
    # a different architecture (e.g. under qemu-user).
    #
    else:
        try:
            ptrace_scope = open('/proc/sys/kernel/yama/ptrace_scope').read().strip()
            if need_ptrace_scope and ptrace_scope != '0' and os.geteuid() != 0:
                msg =  'Disable ptrace_scope to attach to running processes.\n'
                msg += 'More info: https://askubuntu.com/q/41629'
                log.warning(msg)
                return
        except IOError:
            pass

    #
    # Determine which PID we are attaching to, if any.
    #
    pid = None
    if   isinstance(target, (int, long)):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pids = proc.pidof(target)
        if not pids:
            log.error('no such process: %s' % target)
        pid = pids[0]
        log.info('attaching you youngest process "%s" (PID = %d)' %
                 (target, pid))

    #
    # We are attaching to a running process on a remote system.
    #
    elif isinstance(target, tubes.ssh.ssh_channel):

        if not target.pid:
            log.error("PID unknown for channel")

        # The 'parent' object on a 'ssh_channel' object is the SSH session, so that
        # we can run commands on the target machine.
        shell = target.parent

        # We're going to use the local GDB
        if local:
            shell.process(['gdbserver','127.0.0.1:0'])
        else:
            cmd = ['ssh', '-C', '-t', '-p', str(shell.port), '-l', shell.user, shell.host]

        tmpfile = shell.mktemp()
        shell.upload_data(execute or '', tmpfile)

        if shell.password:
            cmd = ['sshpass', '-p', shell.password] + cmd

        if shell.keyfile:
            cmd += ['-i', shell.keyfile]

            cmd += ['gdb %r %s -x "%s" ; rm "%s"' % (target.executable,
                                                     target.pid,
                                                     tmpfile,
                                                     tmpfile)]

        misc.run_in_new_terminal(' '.join(cmd))
        return

    elif isinstance(target, tubes.sock.sock):
        pids = proc.pidof(target)
        if not pids:
            log.error('could not find remote process (%s:%d) on this machine' %
                      target.sock.getpeername())
        pid = pids[0]
    elif isinstance(target, tubes.process.process):
        pid = proc.pidof(target)[0]
    elif isinstance(target, tuple) and len(target) == 2:
        host, port = target
        pre += 'target remote %s:%d\n' % (host, port)
        def findexe():
            # hm no PID then, but wait! we might not be totally out of luck yet: if
            # the gdbserver is running locally and we know the program who is
            # hosting it (e.g qemu, gdbserver) we can figure out the `exe` from the
            # command line

            # find inode of the listen socket
            inode = None

            # XXX: do a proper check to see if we're hosting the server
            if host not in ('localhost', '127.0.0.1', '0.0.0.0',
                            '::1', 'ip6-localhost', '::'):
                return

            for f in ['tcp', 'tcp6']:
                with open('/proc/net/%s' % f) as fd:
                    # skip the first line with the column names
                    fd.readline()
                    for line in fd:
                        line = line.split()
                        loc = line[1]
                        lport = int(loc.split(':')[1], 16)
                        st = int(line[3], 16)
                        if st != 10: # TCP_LISTEN, see include/net/tcp_states.h
                            continue
                        if lport == port:
                            inode = int(line[9])
                            break
                if inode:
                    break

            # if we didn't find the inode, there's nothing we can do about it
            if not inode:
                return

            # find the process who owns the socket
            spid = proc.pid_by_inode(inode)
            if not spid:
                return

            # let's have a look at the server exe
            sexe = proc.exe(spid)
            name = os.path.basename(sexe)
            # XXX: parse cmdline
            if name.startswith('qemu-') or name.startswith('gdbserver'):
                exe = proc.cmdline(spid)[-1]
                return os.path.join(proc.cwd(spid), exe)

        exe = exe or findexe()
    else:
        log.error("don't know how to attach to target: %r" % target)

    # if we have a pid but no exe, just look it up in /proc/
    if pid and not exe:
        exe = proc.exe(pid)

    if not pid and not exe:
        log.error('could not find target process')

    cmd = None
    for p in ('gdb-multiarch', 'gdb'):
        if misc.which(p):
            cmd = p
            break

    if not cmd:
        log.error('no gdb installed')

    if exe:
        if not os.path.isfile(exe):
            log.error('no such file: %s' % exe)
        cmd += ' "%s"' % exe

    if pid:
        cmd += ' %d' % pid

    execute = pre + (execute or '')

    if execute:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',
                                          delete = False)
        tmp.write(execute)
        tmp.close()
        atexit.register(lambda: os.unlink(tmp.name))
        cmd += ' -x "%s" ; rm "%s"' % (tmp.name, tmp.name)

    log.info('running in new terminal: %s' % cmd)
    misc.run_in_new_terminal(cmd)
    if pid:
        proc.wait_for_debugger(pid)
    return pid

def ssh_gdb(ssh, process, execute = None, arch = None, **kwargs):
    if isinstance(process, (list, tuple)):
        exe = process[0]
        process = ["gdbserver", "127.0.0.1:0"] + process
    else:
        exe = process
        process = "gdbserver 127.0.0.1:0 " + process

    # Download the executable
    local_exe = os.path.basename(exe)
    ssh.download_file(exe, local_exe)

    # Run the process
    c = ssh.run(process, **kwargs)

    # Find the port for the gdb server
    c.recvuntil('port ')
    line = c.recvline().strip()
    gdbport = re.match('[0-9]+', line)
    if gdbport:
        gdbport = int(gdbport.group(0))

    l = tubes.listen.listen(0)
    forwardport = l.lport

    attach(('127.0.0.1', forwardport), execute, local_exe, arch)
    l.wait_for_connection() <> ssh.connect_remote('127.0.0.1', gdbport)
    return c

def find_module_addresses(binary, ssh=None, ulimit=False):
    """
    Cheat to find modules by using GDB.

    We can't use ``/proc/$pid/map`` since some servers forbid it.
    This breaks ``info proc`` in GDB, but ``info sharedlibrary`` still works.
    Additionally, ``info sharedlibrary`` works on FreeBSD, which may not have
    procfs enabled or accessible.

    The output looks like this:

    ::

        info proc mapping
        process 13961
        warning: unable to open /proc file '/proc/13961/maps'

        info sharedlibrary
        From        To          Syms Read   Shared Object Library
        0xf7fdc820  0xf7ff505f  Yes (*)     /lib/ld-linux.so.2
        0xf7fbb650  0xf7fc79f8  Yes         /lib32/libpthread.so.0
        0xf7e26f10  0xf7f5b51c  Yes (*)     /lib32/libc.so.6
        (*): Shared library is missing debugging information.

    Note that the raw addresses provided by ``info sharedlibrary`` are actually
    the address of the ``.text`` segment, not the image base address.

    This routine automates the entire process of:

    1. Downloading the binaries from the remote server
    2. Scraping GDB for the information
    3. Loading each library into an ELF
    4. Fixing up the base address vs. the ``.text`` segment address

    Arguments:
        binary(str): Path to the binary on the remote server
        ssh(pwnlib.tubes.tube): SSH connection through which to load the libraries.
            If left as ``None``, will use a ``pwnlib.tubes.process.process``.
        ulimit(bool): Set to ``True`` to run "ulimit -s unlimited" before GDB.

    Returns:
        A list of pwnlib.elf.ELF objects, with correct base addresses.

    Example:

    >>> with context.local(log_level=9999): # doctest: +SKIP
    ...     shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0')
    ...     bash_libs = gdb.find_module_addresses('/bin/bash', shell)
    >>> os.path.basename(bash_libs[0].path) # doctest: +SKIP
    'libc.so.6'
    >>> hex(bash_libs[0].symbols['system']) # doctest: +SKIP
    '0x7ffff7634660'
    """
    #
    # Download all of the remote libraries
    #
    if ssh:
        runner     = ssh.run
        local_bin  = ssh.download_file(binary)
        local_elf  = elf.ELF(os.path.basename(binary))
        local_libs = ssh.libs(binary)

    else:
        runner     = tubes.process.process
        local_elf  = elf.ELF(binary)
        local_libs = local_elf.libs

    entry      = local_elf.header.e_entry

    #
    # Get the addresses from GDB
    #
    libs = {}
    cmd  = "gdb --args %s" % (binary)
    expr = re.compile(r'(0x\S+)[^/]+(.*)')

    if ulimit:
        cmd = 'sh -c "(ulimit -s unlimited; %s)"' % cmd

    cmd = shlex.split(cmd)

    with runner(cmd) as gdb:
        if context.aslr:
            gdb.sendline('set disable-randomization off')
        gdb.send("""
        set prompt
        break *%#x
        run
        """ % entry)
        gdb.clean(2)
        gdb.sendline('info sharedlibrary')
        lines = gdb.recvrepeat(2)

        for line in lines.splitlines():
            m = expr.match(line)
            if m:
                libs[m.group(2)] = int(m.group(1),16)
        gdb.sendline('kill')
        gdb.sendline('y')
        gdb.sendline('quit')

    #
    # Fix up all of the addresses against the .text address
    #
    rv = []

    for remote_path,text_address in sorted(libs.items()):
        # Match up the local copy to the remote path
        try:
            path     = next(p for p in local_libs.keys() if remote_path in p)
        except StopIteration:
            print "Skipping %r" % remote_path
            continue

        # Load it
        lib      = elf.ELF(path)

        # Find its text segment
        text     = lib.get_section_by_name('.text')

        # Fix the address
        lib.address = text_address - text.header.sh_addr
        rv.append(lib)

    return rv
