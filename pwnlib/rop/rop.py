# -*- coding: utf-8 -*-
"""Return Oriented Programming
"""
import collections
import copy
import hashlib
import os
import re
import sys
import tempfile
import random

from operator   import itemgetter

from ..         import abi
from ..         import constants

from ..context  import context
from ..elf      import ELF
from ..log      import getLogger
from ..util     import cyclic
from ..util     import lists
from ..util     import packing
from .          import srop
from .call      import Call, StackAdjustment, AppendedArgument, CurrentStackPointer, NextGadgetAddress
from .gadgets   import Gadget, Mem
from .gadgetfinder  import GadgetFinder, GadgetSolver
from ..util.packing import *

log = getLogger(__name__)
__all__ = ['ROP']


class Padding(object):
    """
    Placeholder for exactly one pointer-width of padding.
    """

class DescriptiveStack(list):
    """
    List of resolved ROP gadgets that correspond to the ROP calls that
    the user has specified.  Also includes
    """

    #: Base address
    address = 0

    #: Dictionary of ``{address: [list of descriptions]}``
    descriptions = {}

    def __init__(self, address):
        self.descriptions = collections.defaultdict(lambda: [])
        self.address      = address or 0

    @property
    def next(self):
        return self.address + len(self) * context.bytes

    def describe(self, text, address = None):
        if address is None:
            address = self.next
        self.descriptions[address] = text

    def dump(self):
        rv = []
        for i, data in enumerate(self):
            addr = self.address + i * context.bytes
            off = None
            line = '0x%04x:' % addr
            if isinstance(data, str):
                line += ' %16r' % data
            elif isinstance(data, (int,long)):
                line += ' %#16x' % data
                if self.address != 0 and self.address < data < self.next:
                    off = data - addr
            else:
                log.error("Don't know how to dump %r" % data)
            desc = self.descriptions.get(addr, '')
            if desc:
                line += ' %s' % desc
            if off is not None:
                line += ' (+%#x)' % off
            rv.append(line)

        return '\n'.join(rv)


class ROP(object):
    r"""Class which simplifies the generation of ROP-chains.

    Example:

    .. code-block:: python

       elf = ELF('ropasaurusrex')
       rop = ROP(elf)
       rop.read(0, elf.bss(0x80))
       rop.dump()
       # ['0x0000:        0x80482fc (read)',
       #  '0x0004:       0xdeadbeef',
       #  '0x0008:              0x0',
       #  '0x000c:        0x80496a8']
       str(rop)
       # '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'

    >>> context.arch = "i386"
    >>> write('/tmp/rop_elf_x86', make_elf(asm('int 0x80; ret; add esp, 0x10; ret; pop eax; ret')))
    >>> e = ELF('/tmp/rop_elf_x86')
    >>> e.symbols['funcname'] = e.address + 0x1234
    >>> r = ROP(e)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> x=r.build()
    >>> print x.dump()
    >>> print r.dump()
    0x0000:        0x8049288 (funcname)
    0x0004:        0x8048057 (add esp, 0x10; ret)
    0x0008:              0x1
    0x000c:              0x2
    0x0010:           '$$$$'
    0x0014:           '$$$$'
    0x0018:        0x8049288 (funcname)
    0x001c:        0x804805b (pop eax; ret)
    0x0020:              0x3
    0x0024:        0x804805b (pop eax; ret)
    0x0028:             0x77
    0x002c:        0x8048054 (int 0x80)
    0x0030:              0x0 (gs)
    0x0034:              0x0 (fs)
    0x0038:              0x0 (es)
    0x003c:              0x0 (ds)
    0x0040:              0x0 (edi)
    0x0044:              0x0 (esi)
    0x0048:              0x0 (ebp)
    0x004c:              0x0 (esp)
    0x0050:              0x4 (ebx)
    0x0054:              0x6 (edx)
    0x0058:              0x5 (ecx)
    0x005c:              0xb (eax)
    0x0060:              0x0 (trapno)
    0x0064:              0x0 (err)
    0x0068:        0x8048054 (eip)
    0x006c:             0x73 (cs)
    0x0070:              0x0 (eflags)
    0x0074:              0x0 (esp_at_signal)
    0x0078:             0x7b (ss)
    0x007c:              0x0 (fpstate)

    >>> r = ROP(e, 0x8048000)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x8048000:        0x8049288 (funcname)
    0x8048004:        0x8048057 (add esp, 0x10; ret)
    0x8048008:              0x1
    0x804800c:              0x2
    0x8048010:           '$$$$'
    0x8048014:           '$$$$'
    0x8048018:        0x8049288 (funcname)
    0x804801c:        0x804805b (pop eax; ret)
    0x8048020:              0x3
    0x8048024:        0x804805b (pop eax; ret)
    0x8048028:             0x77
    0x804802c:        0x8048054 (int 0x80)
    0x8048030:              0x0 (gs)
    0x8048034:              0x0 (fs)
    0x8048038:              0x0 (es)
    0x804803c:              0x0 (ds)
    0x8048040:              0x0 (edi)
    0x8048044:              0x0 (esi)
    0x8048048:              0x0 (ebp)
    0x804804c:        0x8048080 (esp)
    0x8048050:              0x4 (ebx)
    0x8048054:              0x6 (edx)
    0x8048058:              0x5 (ecx)
    0x804805c:              0xb (eax)
    0x8048060:              0x0 (trapno)
    0x8048064:              0x0 (err)
    0x8048068:        0x8048054 (eip)
    0x804806c:             0x73 (cs)
    0x8048070:              0x0 (eflags)
    0x8048074:              0x0 (esp_at_signal)
    0x8048078:             0x7b (ss)
    0x804807c:              0x0 (fpstate)
    """
    #: List of individual ROP gadgets, ROP calls, SROP frames, etc.
    #: This is intended to be the highest-level abstraction that we can muster.
    _chain = []

    #: List of ELF files which are available for mining gadgets
    elfs = []

    #: Stack address where the first byte of the ROP chain lies, if known.
    base = 0

    #: Alignment of the ROP chain; generally the same as the pointer size
    align = 4

    #: Whether or not the ROP chain directly sets the stack pointer to a value
    #: which is not contiguous
    migrated = False

    def __init__(self, elfs, base = None, **kwargs):
        """
        Arguments:
            elfs(list): List of ``pwnlib.elf.ELF`` objects for mining
        """
        #import ropgadget

        # Permit singular ROP(elf) vs ROP([elf])
        if isinstance(elfs, ELF):
            elfs = [elfs]
        elif isinstance(elfs, (str, unicode)):
            elfs = [ELF(elfs)]
        self.elfs = elfs
        self._chain = []
        self.base = base
        self.align = max((e.elfclass for e in elfs)) / 8
        self.migrated = False

        self.arch = elfs[0].arch

        #Find all gadgets
        gf = GadgetFinder(elfs, "all")
        self.gadgets = gf.load_gadgets() 

        self.Verify = gf.solver

        self.initialized = False
        self.builded = False

       
    def __init_classify_and_solver(self):
        """
        Classify and solver gadgets as needed.
        Because of `amoco` has a large initialization-time penalty.
        """
        if not self.initialized:
            self.gadget_graph = self.build_graph(self.gadgets)

            self._global_delete_gadget = {}
            ggh = copy.deepcopy(self.gadget_graph)

            self._top_sorted = self.__build_top_sort(ggh)

            for d, dlist in self._global_delete_gadget.items():
                for i in dlist:
                    self.gadget_graph[d].remove(i)
            

            self.initialized = True
    
    
    def setRegisters(self, values):
        """
        Provides a sequence of ROP gadgets which will set the desired register
        values.

        Arguments:

            values(dict):
                Mapping of ``{register name: value}``.  The contents of
                ``value`` can be any object, not just an integer.

        Return Value:

            Returns a ``collections.OrderedDict`` object which is in the
            correct order of operations.

            The keys are the register names, and the values are the sequence
            of stack values necessary to set the register.

        Example:

            Assume we have the following gadgets.

            1000: pop eax; ret
            2000: mov ebx, eax; ret
            3000: pop ecx; ret
            4000: mov edx, ebx; ret

            For simple cases, the order doesn't matter.
            (Note: The display for OrderedDict is ugly, sorry!)

            >>> set_registers({'eax': 1})
            OrderedDict([('eax', [1000, 1])])
            OrderedDict([('eax', [1000], 8, [(0, 1)])])
            >>> set_registers({'eax': 1, 'ecx': 0})
            OrderedDict([('eax', [1000, 1]), ('ecx', [3000, 0])])
            >>> set_registers({'ebx': None})
            OrderedDict([('ebx', [1000, None, 2000])])

            For complex cases, there is only one possible ordering:

            >>> set_registers({'eax': 1, 'ebx': None})
            OrderedDict([('ebx', [1000, None, 2000]), ('eax', [1000, 1])])

            Sometimes, it may not be possible/

            >>> set_registers({'esi': 0})
            <exception>
        """
        
        # init GadgetSolver and GadgetClassify
        self.__init_classify_and_solver()

        out = []
        ropgadgets = {}
        gadget_list = {}

        if isinstance(values, list):
            values = dict(values)
        
        def md5_insns(path):
            out = []
            for gadget in path:
                out.append("; ".join(gadget.insns)) 

            return hashlib.md5("|".join(out)).hexdigest()

        def record(ropgadget, reg):
            for gadgets in ropgadget:
                all_gadget_address = 0
                all_gadget_address = md5_insns(gadgets)

                ropgadgets[all_gadget_address] = gadgets

                if all_gadget_address not in gadget_list.keys():
                    gadget_list[all_gadget_address] = set()
                gadget_list[all_gadget_address].add(reg)


        for reg, value in values.items():

            ropgadget = self.search_path("sp", [reg])

            if not ropgadget:
                log.error("Gadget to reg %s not found!" % reg)

            # Combine the same gadgets together.
            record(ropgadget, reg)

        ip_reg = {"i386" : "eip",
                  "amd64": "rip",
                  "arm"  : "pc"}
        this_ip = ip_reg[self.arch]
        
        reg_without_ip = values.keys()

        gadget_filter = {}
        # Combine the same gadgets together.
        gadget_list = collections.OrderedDict(sorted(gadget_list.items(), key=lambda t:(-len(t[1]), 
                      len("; ".join([ "; ".join(i.insns) for i in ropgadgets[t[0]]])))))

        middle_set = set(reg_without_ip)
        for all_gadget_address, regs in gadget_list.items():
            if all(i in middle_set for i in regs):
                gadget_filter[all_gadget_address] = regs
                middle_set -= regs 

        for all_gadget_address, regs in gadget_filter.items():
            ropgadget = ropgadgets[all_gadget_address]
            conditions = {}
            for reg in regs:
                conditions[reg] = values[reg]


            result = self.Verify.verify_path(ropgadget, conditions)
            if result:
                sp, stack = result
                out.append(("_".join(regs), (ropgadget, sp, stack)))

        ordered_out = collections.OrderedDict(sorted(out,
                      key=lambda t: self._top_sorted[::-1].index(t[1][0][-1])))
        ordered_out = self.flat_as_on_stack(ordered_out)

        return ordered_out

    def flat_as_on_stack(self, ordered_dict):
        """Convert the values in ordered_dict to the sequence of stack values.

        Arguments:
            ordered_dict(OrderedDict):
                key is register, value is a tuple, its format as follows:
                    (Gadget_object, sp_move(int), value_on_stack(OrderedDict))

        Return:
            out(list):
                A sequence of stack values.
        """

        out = []

        for reg, result in ordered_dict.items():
            outrop = []
            ropgadget, move, _ = result
            sp = 0
            know = {}
            compensate = 0
            for gadget in ropgadget:
                if sp != 0:
                    know[sp] = gadget
                    if gadget.insns[-1].split(" ")[0].strip() == "call":
                        know[sp + 1] = Padding()
                        move += self.align

                sp += gadget.move - self.align

            ropgadget, _, stack_result = result
            outrop.append(ropgadget[0])

            i = 0
            while i < (move - self.align ):
                if i in stack_result.keys():
                    temp_packed = 0
                    for j in range(self.align):
                        temp_packed += stack_result[i+j] << 8*j
                    outrop.append(temp_packed)
                    i += self.align
                elif i in know.keys():
                    outrop.append(know[i])
                    i += self.align
                else:
                    outrop.append(Padding())
                    i += self.align

            out += [(reg, outrop)]

        out = collections.OrderedDict(out)
        return out


    def resolve(self, resolvable):
        """Resolves a symbol to an address

        Arguments:
            resolvable(str,int): Thing to convert into an address

        Returns:
            int containing address of 'resolvable', or None
        """
        if isinstance(resolvable, str):
            for elf in self.elfs:
                if resolvable in elf.symbols:
                    return elf.symbols[resolvable]

        if isinstance(resolvable, (int, long)):
            return resolvable

    def unresolve(self, value):
        """Inverts 'resolve'.  Given an address, it attempts to find a symbol
        for it in the loaded ELF files.  If none is found, it searches all
        known gadgets, and returns the disassembly

        Arguments:
            value(int): Address to look up

        Returns:
            String containing the symbol name for the address, disassembly for a gadget
            (if there's one at that address), or an empty string.
        """
        for elf in self.elfs:
            for name, addr in elf.symbols.items():
                if addr == value:
                    return name

        if value in self.gadgets:
            return '; '.join(self.gadgets[value].insns)
        return ''

    def generatePadding(self, offset, count):
        """
        Generates padding to be inserted into the ROP stack.
        """
        return cyclic.cyclic(offset + count)[-count:]

    def describe(self, object):
        """
        Return a description for an object in the ROP stack
        """
        if isinstance(object, (int, long)):
            return self.unresolve(object)
        if isinstance(object, str):
            return repr(object)
        if isinstance(object, Call):
            return str(object)
        if isinstance(object, Gadget):
            return '; '.join(object.insns)

    def build(self, base = None, description = None):
        """
        Construct the ROP chain into a list of elements which can be passed
        to ``pwnlib.util.packing.flat``.

        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.
            description(dict):
                Optional output argument, which will gets a mapping of
                ``address: description`` for each address on the stack,
                starting at ``base``.
        """
        # This is a flag to avoid rebuilding the ROP chain. 
        # This could save some times.
        if self.builded:
            return self.build_result

        if base is None:
            base = self.base or 0

        stack = DescriptiveStack(base)
        chain = self._chain

        #
        # First pass
        #
        # Get everything onto the stack and save as much descriptive information
        # as possible.
        #
        # The only replacements performed are to add stack adjustment gadgets
        # (to move SP to the next gadget after a Call) and NextGadgetAddress,
        # which can only be calculated in this pass.
        #
        iterable = enumerate(chain)
        for idx, slot in iterable:

            remaining = len(chain) - 1 - idx
            address   = stack.next

            # Integers can just be added.
            # Do our best to find out what the address is.
            if isinstance(slot, (int, long)):
                stack.describe(self.describe(slot))
                stack.append(slot)


            # Byte blobs can also be added, however they must be
            # broken down into pointer-width blobs.
            elif isinstance(slot, (str, unicode)):
                stack.describe(self.describe(slot))
                slot += self.generatePadding(stack.next, len(slot) % context.bytes)

                for chunk in lists.group(context.bytes, slot):
                    stack.append(chunk)

            elif isinstance(slot, srop.SigreturnFrame):
                stack.describe("Sigreturn Frame")

                for register in slot.registers:
                    value       = slot[register]
                    description = self.describe(value)
                    if description:
                        stack.describe('%s = %s' % (register, description))
                    else:
                        stack.describe('%s' % (register))
                    stack.append(value)

            elif isinstance(slot, Call):
                stack.describe(self.describe(slot))

                registers    = dict(zip(slot.abi.register_arguments, slot.args))
                setRegisters = self.setRegisters(registers)

                for register, gadgets in setRegisters.items():
                    regs        = register.split("_")
                    values      = []
                    for reg in regs:
                        if reg != "pc" and reg != "eip" and reg != "rip":
                            values.append(registers[reg])

                    slot_indexs  = [slot.args.index(v) for v in values]
                    description = " | ".join([self.describe(value) for value in values]) \
                            or 'arg%r' % slot_indexs
                    stack.describe('set %s = %s' % (register, description))
                    stack.extend(gadgets)

                if address != stack.next:
                    stack.describe(slot.name)
                
                stack.append(slot.target)

                # For any remaining arguments, put them on the stack
                stackArguments = slot.args[len(slot.abi.register_arguments):]
                nextGadgetAddr = stack.next + (context.bytes * len(stackArguments))

                # Generally, stack-based arguments assume there's a return
                # address on the stack.
                #
                # We need to at least put padding there so that things line up
                # properly, but likely also need to adjust the stack past the
                # arguments.
                if slot.abi.returns:
                    if remaining:
                        fix_size  = (1 + len(stackArguments))
                        fix_bytes = fix_size * context.bytes
                        adjust   = self.search(move = fix_bytes)

                        if not adjust:
                            log.error("Could not find gadget to adjust stack by %#x bytes" % fix_bytes)

                        nextGadgetAddr = stack.next + adjust.move

                        stack.describe('<adjust: %s>' % self.describe(adjust))
                        stack.append(adjust.address)

                        for pad in range(fix_bytes, adjust.move, context.bytes):
                            stackArguments.append(Padding())
                    else:
                        stack.append(Padding())


                for i, argument in enumerate(stackArguments):

                    if isinstance(argument, NextGadgetAddress):
                        stack.describe("<next gadget>")
                        stack.append(nextGadgetAddr)

                    else:
                        stack.describe(self.describe(argument) or 'arg%i' % (i + len(registers)))
                        stack.append(argument)
            else:
                stack.append(slot)
        #
        # Second pass
        #
        # All of the register-loading, stack arguments, and call addresses
        # are on the stack.  We can now start loading in absolute addresses.
        #
        start = base
        end   = stack.next
        size  = (stack.next - base)
        for i, slot in enumerate(stack):
            slot_address = stack.address + (i * context.bytes)
            if isinstance(slot, (int, long)):
                pass

            elif isinstance(slot, (str, unicode)):
                pass

            elif isinstance(slot, AppendedArgument):
                stack[i] = stack.next
                stack.extend(slot.resolve(stack.next))

            elif isinstance(slot, CurrentStackPointer):
                stack[i] = slot_address

            elif isinstance(slot, Padding):
                stack[i] = self.generatePadding(i * context.bytes, context.bytes)
                stack.describe('<pad>', slot_address)

            elif isinstance(slot, Gadget):
                stack[i] = slot.address
                stack.describe(self.describe(slot), slot_address)

            # Everything else we can just leave in place.
            # Maybe the user put in something on purpose?
            # Also, it may work in pwnlib.util.packing.flat()
            else:
                pass

        self.builded = True
        self.build_result = stack

        return stack


    def find_stack_adjustment(self, slots):
        self.search(move=slots * context.arch)

    def chain(self):
        """Build the ROP chain

        Returns:
            str containing raw ROP bytes
        """
        return packing.flat(self.build(), word_size=8 * self.align)

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        return self.build().dump()

    def call(self, resolvable, arguments = (), abi = None, **kwargs):
        """Add a call to the ROP chain

        Arguments:
            resolvable(str,int): Value which can be looked up via 'resolve',
                or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
                Alternately, if a base address is set, arbitrarily nested
                structures of strings or integers can be provided.
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')

        # If we can find a function with that name, just call it
        if isinstance(resolvable, str):
            addr = self.resolve(resolvable)
        else:
            addr = resolvable
            resolvable = ''
        
        if addr:
            self.raw(Call(resolvable, addr, arguments, abi))

        # Otherwise, if it is a syscall we might be able to call it
        elif not self._srop_call(resolvable, arguments):
            log.error('Could not resolve %r.' % resolvable)



    def _srop_call(self, resolvable, arguments):
        # Check that the call is a valid syscall
        resolvable    = 'SYS_' + resolvable.lower()
        syscall_number = getattr(constants, resolvable, None)
        if syscall_number is None:
            return False

        log.info_once("Using sigreturn for %r" % resolvable)

        # Find an int 0x80 or similar instruction we can use
        syscall_gadget       = None
        syscall_instructions = srop.syscall_instructions[context.arch]

        for instruction in syscall_instructions:
            syscall_gadget = self.find_gadget([instruction])
            if syscall_gadget:
                break
        else:
            log.error("Could not find any instructions in %r" % syscall_instructions)

        # Generate the SROP frame which would invoke the syscall
        with context.local(arch=self.arch):
            frame         = srop.SigreturnFrame()
            frame.pc      = syscall_gadget
            frame.syscall = syscall_number
            SYS_sigreturn  = constants.SYS_sigreturn
            for register, value in zip(frame.arguments, arguments):
                frame[register] = value

        # Set up a call frame which will set EAX and invoke the syscall
        call = Call('SYS_sigreturn',
                    syscall_gadget,
                    [SYS_sigreturn],
                    abi.ABI.sigreturn())

        self.raw(call)
        self.raw(frame)


        # We do not expect to ever recover after the syscall, as it would
        # require something like 'int 0x80; ret' which does not ever occur
        # in the wild.
        self.migrated = True

        return True

    def find_gadget(self, instructions):
        """
        Returns a gadget with the exact sequence of instructions specified
        in the ``instructions`` argument.
        """
        for gadget in self.gadgets.values():
            if tuple(gadget.insns) == tuple(instructions):
                return gadget

    def raw(self, value):
        """Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Arguments:
            data(int/str): The raw value to put onto the rop chain.
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')
        self._chain.append(value)

    def migrate(self, next_base):
        """Explicitly set $sp, by using a ``leave; ret`` gadget"""
        if isinstance(next_base, ROP):
            next_base = self.base
        pop_sp = self.rsp or self.esp
        pop_bp = self.rbp or self.ebp
        leave  = self.leave
        if pop_sp and len(pop_sp.regs) == 1:
            self.raw(pop_sp)
            self.raw(next_base)
        elif pop_bp and leave and len(pop_bp.regs) == 1:
            self.raw(pop_bp)
            self.raw(next_base - 4)
            self.raw(leave)
        else:
            log.error('Cannot find the gadgets to migrate')
        self.migrated = True

    def __str__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain()

    def __repr__(self):
        return 'ROP(%r)' % self.elfs

    def search_iter(self, move=None, regs=None):
        """
        Iterate through all gadgets which move the stack pointer by
        *at least* ``move`` bytes, and which allow you to set all
        registers in ``regs``.
        """
        move = move or 0
        regs = set(regs or ())

        for addr, gadget in self.gadgets.items():
            if gadget.move < move:          continue
            if not (regs <= set(gadget.regs)):   continue
            yield gadget

    def search(self, move = 0, regs = None, order = 'size'):
        """Search for a gadget which matches the specified criteria.

        Arguments:
            move(int): Minimum number of bytes by which the stack
                pointer is adjusted.
            regs(list): Minimum list of registers which are popped off the
                stack.
            order(str): Either the string 'size' or 'regs'. Decides how to
                order multiple gadgets the fulfill the requirements.

        The search will try to minimize the number of bytes popped more than
        requested, the number of registers touched besides the requested and
        the address.

        If ``order == 'size'``, then gadgets are compared lexicographically
        by ``(total_moves, total_regs, addr)``, otherwise by ``(total_regs, total_moves, addr)``.

        Returns:
            A ``pwnlib.rop.gadgets.Gadget`` object
        """
        matches = self.search_iter(move, regs)
        if matches is None:
            return None

        # Search for an exact match, save the closest match
        key = {
            'size': lambda g: (g.move, len(g.regs), g.address),
            'regs': lambda g: (len(g.regs), g.move, g.address)
        }[order]

        try:
            return min(matches, key=key)
        except ValueError:
            return None

    def __getattr__(self, attr):
        """Helper to make finding ROP gadets easier.

        Also provides a shorthand for ``.call()``:
            ``rop.function(args)`` is equivalent to ``rop.call(function, args)``

        >>> elf=ELF(which('bash'))
        >>> rop=ROP([elf])
        >>> rop.rdi     == rop.search(regs=['rdi'], order = 'regs')
        True
        >>> rop.r13_r14_r15_rbp == rop.search(regs=['r13','r14','r15','rbp'], order = 'regs')
        True
        >>> rop.ret_8   == rop.search(move=8)
        True
        >>> rop.ret     != None
        True
        """
        gadget = collections.namedtuple('gadget', ['address', 'details'])
        bad_attrs = [
            'trait_names',          # ipython tab-complete
            'download',             # frequent typo
            'upload',               # frequent typo
        ]

        if attr in self.__dict__ \
        or attr in bad_attrs \
        or attr.startswith('_'):
            raise AttributeError('ROP instance has no attribute %r' % attr)

        #
        # Check for 'ret' or 'ret_X'
        #
        if attr.startswith('ret'):
            count = 4
            if '_' in attr:
                count = int(attr.split('_')[1])
            return self.search(move=count)

        if attr in ('int80', 'syscall', 'sysenter'):
            mapping = {'int80': u'int 0x80',
             u'syscall': u'syscall',
             'sysenter': u'sysenter'}
            for each in self.gadgets:
                if self.gadgets[each]['insns'] == [mapping[attr]]:
                    return gadget(each, self.gadgets[each])
            return None

        #
        # Check for a '_'-delimited list of registers
        #
        x86_suffixes = ['ax', 'bx', 'cx', 'dx', 'bp', 'sp', 'di', 'si',
                        'r8', 'r9', '10', '11', '12', '13', '14', '15']

        if all(map(lambda x: x[-2:] in x86_suffixes, attr.split('_'))):
            return self.search(regs=attr.split('_'), order='regs')

        #
        # Otherwise, assume it's a rop.call() shorthand
        #
        def call(*args):
            return self.call(attr, args)

        return call

    def build_graph(self, gadgets):
        '''Build gadgets graph, gadget as vertex, reg as edge.

        Arguments:
            
            gadgets(dict):
                { address: Gadget object }

        Returns: dict, Graph in adjacency list format. 

        Example:
            
            Assume we have the following gadgets.

            Gadget01 ==> 1000: pop eax; ret
            Gadget02 ==> 2000: mov ebx, eax; ret
            Gadget03 ==> 3000: pop ecx; ret
            Gadget04 ==> 4000: mov edx, ebx; ret

            >>> build_graph(gadgets)
            {Gadget01 : [Gadget02], 
             Gadget02 : [Gadget04],
             Gadget03 : [],
             Gadget04 : []}
            
        '''
        gadget_graph = {}
        for gad_1 in gadgets.values():
            gadget_graph[gad_1] = set()
            outputs = []
            for i in gad_1.regs.keys():
                if isinstance(i, (str, unicode)) and ("ip" not in i and "pc" not in i):

                    # Drop gadgets which set to themselves.
                    # For {"esp":["esp"]} or {"eax":"eax"}
                    in_reg = gad_1.regs[i]
                    if isinstance(in_reg, list):
                        in_reg = "".join(in_reg)

                    if in_reg != i:
                        outputs.append(i)

            for gad_2 in gadgets.values():
                if gad_1 == gad_2:
                    continue
                inputs=[]
                for k, i in gad_2.regs.items():

                    # Drop gadgets which set to themselves.
                    # For {"esp":["esp"]} or {"eax":"eax"}
                    if isinstance(i, (str, unicode)):
                        if k != i:
                            inputs.append(i)
                    elif isinstance(i, list):
                        if k != "".join(i):
                            inputs += i

                inter = set(inputs) & set(outputs)
                if len(inter) > 0:
                    gadget_graph[gad_1].add(gad_2)

        return gadget_graph


    def __build_top_sort(self, graph):
        """
        Topological sort a graph.

        Arguments:
            
            graph(dict):
                A simple example : graph = {'eax': ['ebx'], 'ebx': ['eax'], 'edx': ['eax']}
                May be cycles in graph. we need to handle it.

        Returns:
            top_sorted(list):
                such as: ["edx", "eax", "ebx"]
        """
        top_sorted = []
        indegree_zero = []

        #Inital indegree list will zero.
        indegree = {}
        for k, v in graph.items():
            indegree[k] = 0
            for l in v:
                indegree[l] = 0

        #Caculate indegree, for gadget graph.
        for g, glist in graph.items():
            for gadget in glist:
                indegree[gadget] += 1

        #inital indegree_zero list.
        for g, indeg in indegree.items():
            if indeg == 0:
                indegree_zero.append(g)
        
        # TOP sort
        while len(indegree_zero) > 0:
            n = indegree_zero.pop()
            top_sorted.append(n)

            if n not in graph.keys():
                continue

            for m in graph[n]:
                indegree[m] -= 1
                if indegree[m] == 0:
                    indegree_zero.append(m)
            del(graph[n])
        
        if len(graph) == 0:
            return top_sorted
        
        # Recursive top sort.
        for g, indeg in indegree.items():
            if indeg >= 1:
                for k, glist in graph.items():
                    for h in glist.copy():
                        if h == g:
                            graph[k].remove(h)
                            #record the deleted edge of cirles.
                            if k not in self._global_delete_gadget.keys():
                                self._global_delete_gadget[k] = set()
                            self._global_delete_gadget[k].add(h)
                            
        # Recurisve top sorting.
        last_result = self.__build_top_sort(graph)
        if not last_result:
            last_result = []

        return top_sorted + last_result


    def search_path(self, src, regs):
        '''Search paths, from src to regs.
        Example: search("rsp", ["rdi"]), such as gadget "pop rdi; ret" will be return to us.
        '''
        start = set()
        for gadget in self.gadgets.values():
            gadget_srcs = []
            for k,i in gadget.regs.items():
                if isinstance(i , Mem):
                    gadget_srcs.append(i.reg)
                elif isinstance(i, list):
                    if k not in str(i):
                        gadget_srcs.extend([str(x) for x in i])
                elif isinstance(i, str):
                    if k != i:
                        gadget_srcs.append(i)
            if any([src in i for i in gadget_srcs]):
                start.add(gadget)

        end = set()
        alldst = {}
        for reg in regs:
            alldst[reg] = set()

        asm_instr_dict = {}
        for gadget in self.gadgets.values():
            the_insns = "; ".join(gadget.insns)
            asm_instr_dict[the_insns] = gadget
            gadget_dsts = []
            for k, i in gadget.regs.items():
                if isinstance(i, list):
                    if k not in str(i):
                        gadget_dsts.append(k)
                elif isinstance(i, str):
                    if k != i:
                        gadget_dsts.append(k)
            for reg in regs:
                if reg in gadget_dsts:
                    alldst[reg].add(the_insns)

        dstlist = alldst.values()
        results = reduce(set.intersection, dstlist)
        for r in results:
            end.add(asm_instr_dict[r])
        
        paths = []
        if len(start) != 0 and len(end) != 0:
            for s in list(start):
                for e in list(end):
                    path = self.__dfs(self.gadget_graph, s, e)
                    paths += list(path)

        # Give every reg a random num
        cond = {}
        for reg in regs:
            cond[reg] = random.randint(2**16, 2**32)
        
        # Solve this gadgets arrangement, if stack's value not changed, ignore it.
        path_filted = []
        for path in paths:
            out = self.Verify.verify_path(path, cond)
            if out:
                path_filted.append(path)

        paths = sorted(path_filted, 
                key=lambda path: len(" + ".join(["; ".join(gad.insns) for gad in path])))

        if not paths:
            return None

        return paths


    def __dfs(self, graph, start, end, path=[]):
        '''DFS for find a path in any graph.
        '''
        path = path + [start]

        if start == end:
            yield path
        if not graph.has_key(start):
            return
        for node in graph[start]:
            if node not in path:
                for new_path in self.__dfs(graph, node, end, path):
                    if new_path:
                        yield new_path
