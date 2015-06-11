# -*- coding: utf-8 -*-

import re
import os
import types
import hashlib
import tempfile
import operator

from ..log     import getLogger
from ..elf     import ELF
from .gadgets  import Gadget, Mem

import amoco
import amoco.system.raw
import amoco.system.core
import amoco.cas.smt

from BTrees.OOBTree import OOBTree
from amoco.cas.expressions import *
from z3          import *
from collections import OrderedDict
from operator    import itemgetter


log = getLogger(__name__)

# File size more than 100kb, should be filter for performance trade off
MAX_SIZE = 100

class GadgetMapper(object):
    r"""Get the gadgets mapper in symbolic expressions.
    
    This is the base class for GadgetSolver and GadgetClassifier.

    """

    def __init__(self, arch, mode):
        '''Base class which can symbolic execution gadget instructions.
        '''
        from capstone import CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB
        self.arch = arch
        
        self.for_arm = False
        if arch == CS_ARCH_X86 and mode == CS_MODE_32:
            import amoco.arch.x86.cpu_x86 as cpu 
            self.align = 4
        elif arch == CS_ARCH_X86 and mode == CS_MODE_64:
            import amoco.arch.x64.cpu_x64 as cpu 
            self.align = 8
        elif arch == CS_ARCH_ARM and mode == CS_MODE_ARM:
            import amoco.arch.arm.cpu_armv7 as cpu 
            self.internals = 0
            self.align = 4
        elif arch == CS_ARCH_ARM and mode == CS_MODE_THUMB:
            import amoco.arch.arm.cpu_armv7 as cpu 
            self.for_arm = True
            self.internals = 1
            self.align = 4
        else:
            raise Exception("Unsupported archtecture %s." % arch)

        self.cpu = cpu

    def sym_exec_gadget_and_get_mapper(self, code):
        '''This function gives you a ``mapper`` object from assembled `code`. 
        `code` will basically be our assembled gadgets.

        Arguments: 
            code(str): The raw bytes of gadget which you want to symbolic execution.

        Return:
            A mapper object.
            Example:
                [u'pop rdi', u'ret '] ==> "\x5f\xc3"
                sym_exec_gadget_and_get_mapper("\x5f\xc3")

                Return a mapper object:
                    rdi <- { | [0:64]->M64(rsp) | }
                    rip <- { | [0:64]->M64(rsp+8) | }
                    rsp <- { | [0:64]->(rsp+0x10) | }

        Note that `call`s will be neutralized in order to not mess-up the 
        symbolic execution (otherwise the instruction just after the `call 
        is considered as the instruction being jumped to).
        
        From this ``mapper`` object you can reconstruct the symbolic CPU state 
        after the execution of your gadget.

        The CPU used is x86, but that may be changed really easily, so no biggie.

        Taken from https://github.com/0vercl0k/stuffz/blob/master/look_for_gadgets_with_equations.py'''
        if self.for_arm:
            from amoco.arch.arm.v7.env import internals
            internals["isetstate"] = self.internals

        p = amoco.system.raw.RawExec(
            amoco.system.core.DataIO(code), self.cpu
        )
        blocks = list(amoco.lsweep(p).iterblocks())
        if len(blocks) == 0:
            return None
        #assert(len(blocks) > 0)
        mp = amoco.cas.mapper.mapper()
        for block in blocks:
            # If the last instruction is a call, we need to "neutralize" its effect
            # in the final mapper, otherwise the mapper thinks the block after that one
            # is actually 'the inside' of the call, which is not the case with ROP gadgets
            if block.instr[-1].mnemonic.lower() == 'call':
                p.cpu.i_RET(None, block.map)
            try:
                mp >>= block.map
            except:
                mp = None

        return mp

class GadgetClassifier(GadgetMapper):
    r"""Classify gadgets to decide its sp_move value and regs relationship.

    Example:

    .. code-block:: python
        gc = GadgetClassifier("amd64")
        newGadget = gc.classify(oldGadget)

    """

    def __init__(self, arch, mode):
        super(GadgetClassifier, self).__init__(arch, mode)
    
    def classify(self, gadget):
        """Classify gadgets, get the regs relationship, and sp move. 

        Arguments:
            gadget(Gadget object), with sp == 0 and regs = {}

        Return:
            Gadget object with correct sp move value and regs relationship

        Example:
            assume gadget_test = Gadget(address:0x1000, [u'pop rdi', u'ret'], {}, 0x0) 
            >>> classify(gadget_test) 
            Gadget(address:0x1000, [u'pop rdi', u'ret'], {"rdi":Mem(reg: "rsp", offset: 0, size:64)}, 0x10) 
        """
        address = gadget.address
        insns   = gadget.insns
        bytes   = gadget.bytes
         
        gadget_mapper = self.sym_exec_gadget_and_get_mapper(bytes)
        if not gadget_mapper:
            return None

        regs = {}
        move = 0
        ip_move = 0
        for reg_out, _ in gadget_mapper:
            if reg_out._is_ptr or reg_out._is_mem:
                return None

            if "flags" in str(reg_out) or "apsr" in str(reg_out):
                continue

            inputs = gadget_mapper[reg_out]

            if "sp" in str(reg_out):
                move = extract_offset(inputs)[1]
                continue

            if "ip" in str(reg_out):
                if inputs._is_mem:
                    ip_move = inputs.a.disp 
                    continue

            if "pc" in str(reg_out):
                if isinstance(inputs, mem):
                    ip_move = inputs.a.disp
                    reg_mem = locations_of(inputs)
                    reg_str = "_".join([str(i) for i in reg_mem])
                    if "sp" not in reg_str:
                        return None
                elif isinstance(inputs, op):
                    ip_move = extract_offset(inputs)[1]

                if ip_move != 0:
                    continue


            if inputs._is_mem:
                offset = inputs.a.disp 
                reg_mem = locations_of(inputs)

                if isinstance(reg_mem, list):
                    reg_str = "_".join([str(i) for i in reg_mem])
                else:
                    reg_str = str(reg_mem)

                reg_size = inputs.size
                regs[str(reg_out)] = Mem(reg_str, offset, reg_size)

            elif inputs._is_reg:
                regs[str(reg_out)] = str(inputs)

            elif inputs._is_cst:
                regs[str(reg_out)] = inputs.value

            elif isinstance(inputs, list) or isinstance(inputs, types.GeneratorType):
                regs[str(reg_out)] = [str(locations_of(i) for i in inputs)]

            else:
                allregs = locations_of(inputs)
                if isinstance(allregs, list):
                    allregs = [str(i) for i in allregs]
                elif isinstance(allregs, reg):
                    allregs = str(allregs)
                regs[str(reg_out)] = allregs
        
        if "pop" in insns[-1] and ip_move != (move - self.align):
            return None
        elif not regs and not move:
            return None
        else:
            return Gadget(address, insns, regs, move, bytes)



class GadgetSolver(GadgetMapper):
    r"""Solver a gadget path to satisfy some conditions.

    Example:

    .. code-block:: python
        gs = GadgetSolver(CS_ARCH_X86, CS_MODE_64) 
        conditions = {"rdi" : 0xbeefdead}
        sp_move, stack_result = gs.verify_path(gadget_path, conditions)

    """

    def __init__(self, arch, mode):
        super(GadgetSolver, self).__init__(arch, mode)

    def _prove(self, expression):
        s = Solver()
        s.add(expression)
        if s.check() == sat:
            return s.model()
        return None

    def verify_path(self, path, conditions={}):
        """Solve a gadget path, get the sp move and which values should be on stack. 

        Arguments:
            
            path(list): Gadgets arrangement from reg1/mem to reg2
                ["pop ebx; ret", "mov eax, ebx; ret"]

            conditions(dict): the result we want.
                {"eax": 0xbeefdead}, after gadgets in path executed, we want to assign 0xbeefdead to eax.

        Returns:
            
            tuple with two items
            first item is sp move
            second is which value should on stack, before gadgets in path execute
            For the example above, we will get:
                (12, OrderedDict{0:"\xad", 1:"\xde", 2:"\xef", 3:"\xbe"})
        """
        concate_bytes = "".join([gadget.bytes for gadget in path])
        gadget_mapper = self.sym_exec_gadget_and_get_mapper(concate_bytes)

        stack_changed = []
        move = 0
        for reg, constraint in gadget_mapper:
            if "sp" in str(reg):
                move = extract_offset(gadget_mapper[reg])[1]
                continue

            if str(reg) in conditions.keys():
                model = self._prove(conditions[str(reg)] == constraint.to_smtlib())
                if not model:
                    return None

                sp_reg = locations_of(gadget_mapper[reg])
                if isinstance(sp_reg, list):
                    sp_reg = [str(i) for i in sp_reg]
                else:
                    sp_reg = str(sp_reg)
                if gadget_mapper[reg]._is_mem and any(["sp" in i for i in sp_reg]):
                    num = model[model[1]].num_entries()
                    stack_changed += model[model[1]].as_list()[:num]

        if len(stack_changed) == 0:
            return None

        stack_converted = [(i[0].as_signed_long(), i[1].as_long()) for i in stack_changed]
        stack_changed = OrderedDict(sorted(stack_converted, key=itemgetter(0)))

        return (move, stack_changed)


class GadgetFinder(object):
    r"""Finding gadgets for specified elfs. 

    Example:

    .. code-block:: python
        
        elf = ELF('ropasaurusrex')
        gf = GadgetFinder(elf)
        gadgets = gf.load_gadgets()

    """

    def __init__(self, elfs, gadget_filter="all", depth=10):
        
        import capstone 
        self.capstone = capstone

        if isinstance(elfs, ELF):
            filename = elfs.file.name
            elfs = [elfs]
        elif isinstance(elfs, (str, unicode)):
            filename = elfs
            elfs = [ELF(elfs)]
        elif isinstance(elfs, (tuple, list)):
            filename = elfs[0].file.name
        else:
            log.error("ROP: Cannot load such elfs.")

        self.elfs = elfs

        # Maximum instructions lookahead bytes.
        self.depth = depth
        self.gadget_filter = gadget_filter
        
        x86_gadget = { 
                "ret":      [["\xc3", 1, 1],               # ret
                            ["\xc2[\x00-\xff]{2}", 3, 1],  # ret <imm>
                            ],
                #"jmp":      [["\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1], # jmp  [reg]
                            #["\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                            #["\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1], # jmp  [reg]
                            #],
                #"call":     [["\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1],  # call  [reg]
                            #],
                "int":      [["\xcd\x80", 2, 1], # int 0x80
                            ],
                "sysenter": [["\x0f\x34", 2, 1], # sysenter
                            ],
                "syscall":  [["\x0f\x05", 2, 1], # syscall
                            ]}
        all_x86_gadget = reduce(lambda x, y: x + y, x86_gadget.values())
        x86_gadget["all"] = all_x86_gadget

        arm_gadget = {
                "ret":  [["[\x00-\xff]{1}[\x80-\x8f]{1}\xbd\xe8", 4, 4],       # pop {,pc}
                        ],
                #"bx":   [["[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                        #],
                #"blx":  [["[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                        #],
                "svc":  [["\x00-\xff]{3}\xef", 4, 4] # svc
                        ],
                }
        all_arm_gadget = reduce(lambda x, y: x + y, arm_gadget.values())
        arm_gadget["all"] = all_arm_gadget

        arm_thumb = {
                "ret": [["[\x00-\xff]{1}\xbd", 2, 2], # pop {,pc}
                    ],
                #"bx" : [["[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                    #],
                #"blx": [["[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                    #],
                "svc": [["\x00-\xff]{1}\xef", 2, 2], # svc
                    ],
                }
        all_arm_gadget = reduce(lambda x, y: x + y, arm_thumb.values())
        arm_thumb["all"] = arm_thumb 


        self.arch_mode_gadget = {
                "i386"  : (self.capstone.CS_ARCH_X86, self.capstone.CS_MODE_32,     x86_gadget[gadget_filter]),
                "amd64" : (self.capstone.CS_ARCH_X86, self.capstone.CS_MODE_64,     x86_gadget[gadget_filter]),
                "arm": (self.capstone.CS_ARCH_ARM, self.capstone.CS_MODE_ARM,    arm_gadget[gadget_filter]),
                "thumb"   : (self.capstone.CS_ARCH_ARM, self.capstone.CS_MODE_THUMB,  arm_thumb[gadget_filter]),
                }
        if self.elfs[0].arch not in self.arch_mode_gadget.keys():
            raise Exception("Architecture not supported.")
        
        bin_arch = self.elfs[0].arch

        self.arch, self.mode, self.gadget_re = self.arch_mode_gadget[bin_arch]
        self.need_filter = False
        if self.arch == self.capstone.CS_ARCH_X86 and len(self.elfs[0].file.read()) >= MAX_SIZE*1000:
            self.need_filter = True

        self.classifier = GadgetClassifier(self.arch, self.mode)
        self.solver     = GadgetSolver(self.arch, self.mode)



    def load_gadgets(self):
        """Load all ROP gadgets for the selected ELF files
        """

        out = OOBTree()
        for elf in self.elfs:

            gadget_db = GadgetDatabase(elf)
            gads = gadget_db.load_gadgets()


            if not gads:
                gg = []
                for seg in elf.executable_segments:
                    gg += self.__find_all_gadgets(seg, self.gadget_re, elf)

                gg = self.__deduplicate(gg)
                out.update(gadget_db.save_gadgets(gg))

            else:
                out.update(gads)

        return out


    def __find_all_gadgets(self, section, gadget_re, elf):
        '''Find gadgets like ROPgadget do.
        '''
        C_OP = 0
        C_SIZE = 1
        C_ALIGN = 2
        
        allgadgets = []
        insns_hashtable = []

        for gad in gadget_re:
            allRef = [m.start() for m in re.finditer(gad[C_OP], section.data())]
            for ref in allRef:
                for i in range(self.depth):
                    md = self.capstone.Cs(self.arch, self.mode)
                    md.detail = True
                    back_bytes = i * gad[C_ALIGN]
                    section_start = ref - back_bytes
                    start_address = section.header.p_vaddr + section_start
                    if elf.elftype == 'DYN':
                        start_address = elf.address + start_address

                    decodes = md.disasm(section.data()[section_start : ref + gad[C_SIZE]], 
                                        start_address)

                    insns = []
                    decodes = list(decodes)
                    for decode in decodes:
                        insns.append((decode.mnemonic + " " + decode.op_str).strip())
                    
                    if len(insns) > 0:
                        if (start_address % gad[C_ALIGN]) == 0:
                            reg     = {}
                            move    = 0
                            address = start_address
                            bytes   = section.data()[ref - (i*gad[C_ALIGN]):ref+gad[C_SIZE]]
                            onegad = Gadget(address, insns, reg, move, bytes)

                            if hashlib.sha1("; ".join(insns)).hexdigest() in insns_hashtable:
                                continue
                            if not self.__passClean(decodes):
                                continue

                            if self.need_filter:
                                onegad = self.__filter_for_big_binary_or_elf32(onegad)
                            insns_hashtable.append(hashlib.sha1("; ".join(insns)).hexdigest())
                            if onegad:
                                onegad = self.classifier.classify(onegad)

                            if onegad: 
                                allgadgets += [onegad]

        return allgadgets

    def __filter_for_big_binary_or_elf32(self, gadget):
        '''Filter gadgets for big binary.
        '''
        new = None
        pop   = re.compile(r'^pop (.{3})')
        add   = re.compile(r'^add .sp, (\S+)$')
        ret   = re.compile(r'^ret$')
        leave = re.compile(r'^leave$')
        mov   = re.compile(r'^mov (.{3}), (.{3})')
        xchg  = re.compile(r'^xchg (.{3}), (.{3})')
        int80 = re.compile(r'int +0x80')
        syscall = re.compile(r'^syscall$')
        sysenter = re.compile(r'^sysenter$')

        valid = lambda insn: any(map(lambda pattern: pattern.match(insn), 
            [pop,add,ret,leave,xchg,mov,int80,syscall,sysenter]))

        insns = gadget.insns
        if all(map(valid, insns)):
            new = gadget

        return new

    def __checkMultiBr(self, decodes, branch_groups):
        """Caculate branch number for __passClean().
        """
        count = 0
        pop_pc = re.compile('^pop.* \{.*pc\}') 
        for inst in decodes:
            insns = inst.mnemonic + " " + inst.op_str
            if pop_pc.match(insns):
                count += 1

            for group in branch_groups:
                if group in inst.groups:
                    count += 1
        return count
    
    def __passClean(self, decodes, multibr=False):
        """Filter gadgets with two more blocks.
        """
        
        branch_groups = [self.capstone.CS_GRP_JUMP, 
                         self.capstone.CS_GRP_CALL, 
                         self.capstone.CS_GRP_RET, 
                         self.capstone.CS_GRP_INT, 
                         self.capstone.CS_GRP_IRET]

        # "pop {.*pc}" for arm
        # Because Capstone cannot identify this instruction as Branch instruction
        pop_pc = re.compile('^pop \{.*pc\}') 
        last_instr = (decodes[-1].mnemonic + " " + decodes[-1].op_str)

        if (not pop_pc.match(last_instr)) and (not (set(decodes[-1].groups) & set(branch_groups))):
            return False

        if not multibr and self.__checkMultiBr(decodes, branch_groups) > 1:
            return False
        
        return True
    
    def __deduplicate(self, gadgets):
        new, insts = [], []
        for gadget in gadgets:
            insns = "; ".join(gadget.insns) 
            if insns in insts:
                continue
            insts.append(insns)
            new += [gadget]
        return new


class GadgetDatabase(object):
    """A Gadget database object to store gadget easily.
    """

    def __init__(self, elf):
        self.elfname = elf.file.name
        self.dbname = self.get_db_name(elf)
        self.db     = self.get_db()

    def get_db_name(self, elf):
        basename = os.path.basename(elf.file.name)
        sha256   = hashlib.sha256(elf.get_data()).hexdigest()
        cachedir = os.path.join(tempfile.gettempdir(), 'binjitsu-rop-cache')

        if not os.path.exists(cachedir):
            os.mkdir(cachedir)

        return os.path.join(cachedir, sha256)

    def get_db(self):
        import ZODB, ZODB.FileStorage

        storage = ZODB.FileStorage.FileStorage(self.dbname)
        db = ZODB.DB(storage)
        connection = db.open()
        root = connection.root()
        return root

    def save_gadgets(self, gadgets):
        import transaction

        if not self.db.has_key("gadgets"):
            self.db['gadgets'] = OOBTree()

        gadget_db = self.db["gadgets"]
        for gadget in gadgets:
            gadget_db[gadget.address] = gadget

        transaction.commit()
        return gadget_db

    def load_gadgets(self):

        if not self.db.has_key("gadgets"):
            return None

        if len(self.db["gadgets"]) == 0:
            return None
        
        log.info_once("Loaded cached gadgets for %r" % self.elfname)

        return self.db["gadgets"]
