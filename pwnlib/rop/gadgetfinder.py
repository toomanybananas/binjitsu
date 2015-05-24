# -*- coding: utf-8 -*-

import re
import os
import hashlib
import capstone
import tempfile

from ..log     import getLogger

log = getLogger(__name__)

# File size more than 100kb, should be filter for performance trade off
MAX_SIZE = 100

class GadgetFinder(object):

    def __init__(self, elfs, gadget_filter="all", depth=10):

        self.elfs = elfs

        # Maximum instructions lookahead bytes.
        self.depth = depth
        self.gadget_filter = gadget_filter
        
        x86_gadget = { 
                "ret":      [["\xc3", 1, 1],               # ret
                            ["\xc2[\x00-\xff]{2}", 3, 1],  # ret <imm>
                            ],
                "jmp":      [["\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1], # jmp  [reg]
                            ["\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                            ["\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1], # jmp  [reg]
                            ],
                "call":     [["\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1],  # call  [reg]
                            ],
                "int":      [["\xcd\x80", 2, 1], # int 0x80
                            ],
                "sysenter": [["\x0f\x34", 2, 1], # sysenter
                            ],
                "syscall":  [["\x0f\x05", 2, 1], # syscall
                            ]}
        all_x86_gadget = reduce(lambda x, y: x + y, x86_gadget.values())
        x86_gadget["all"] = all_x86_gadget

        arm_gadget = {
                "ret":  [["[\x00-\xff]{1}\x80\xbd\xe8", 4, 4],       # pop {,pc}
                        ],
                "bx":   [["[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                        ],
                "blx":  [["[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                        ],
                "svc":  [["\x00-\xff]{3}\xef", 4, 4] # svc
                        ]}
        all_arm_gadget = reduce(lambda x, y: x + y, arm_gadget.values())
        arm_gadget["all"] = all_arm_gadget


        arch_mode_gadget = {
                "i386"  : (capstone.CS_ARCH_X86, capstone.CS_MODE_32,  x86_gadget[gadget_filter]),
                "amd64" : (capstone.CS_ARCH_X86, capstone.CS_MODE_64,  x86_gadget[gadget_filter]),
                "arm"   : (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, arm_gadget[gadget_filter]),
                }

        if self.elfs[0].arch not in arch_mode_gadget.keys():
            raise Exception("Architecture not supported.")

        self.arch, self.mode, self.gadget_re = arch_mode_gadget[self.elfs[0].arch]
        if self.arch == capstone.CS_ARCH_X86 and len(self.elf[0].file.read()) >= MAX_SIZE*1000:
            self.need_filter = True


    def load_gadgets(self):
        """Load all ROP gadgets for the selected ELF files
        New feature: 1. Without ROPgadget
                     2. Extract all gadgets, including ret, jmp, call, syscall, sysenter.
        """

        out = []
        for elf in self.elfs:
            gadgets = []
            for seg in elf.executable_segments:
                gadgets += self.__find_all_gadgets(seg, self.gadget_re, elf)
            
            if self.arch == capstone.CS_ARCH_X86:
                gadgets = self.__passCleanX86(gadgets)
            gadgets = self.__deduplicate(gadgets)

            #build for cache
            data = {}
            for gad in gadgets:
                data[gad["address"]] = gad["bytes"]
            self.__cache_save(elf, data)

            out += gadgets

        return out


    def __find_all_gadgets(self, section, gadgets, elf):
        '''Find gadgets like ROPgadget do.
        '''
        C_OP = 0
        C_SIZE = 1
        C_ALIGN = 2
        
        allgadgets = []

        # Recover gadgets from cached file.
        cache = self.__cache_load(elf)
        if cache:
            for k, v in cache.items():
                md = capstone.Cs(self.arch, self.mode)
                decodes = md.disasm(v, k)
                ldecodes = list(decodes)
                gadget = ""
                for decode in ldecodes:
                    gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                if len(gadget) > 0:
                    gadget = gadget[:-3]
                    onegad = {}
                    onegad["address"] = k
                    onegad["gad_instr"] = ldecodes
                    onegad["gadget"] = gadget
                    onegad["bytes"] = v
                    allgadgets += [onegad]
            return allgadgets

        for gad in gadgets:
            allRef = [m.start() for m in re.finditer(gad[C_OP], section.data())]
            for ref in allRef:
                for i in range(self.depth):
                    md = capstone.Cs(self.arch, self.mode)
                    #md.detail = True
                    if elf.elftype == 'DYN':
                        startAddress = elf.address + section.header.p_vaddr + ref - (i*gad[C_ALIGN])
                    else:
                        startAddress = section.header.p_vaddr + ref - (i*gad[C_ALIGN])

                    decodes = md.disasm(section.data()[ref - (i*gad[C_ALIGN]):ref+gad[C_SIZE]], 
                                        startAddress)
                    ldecodes = list(decodes)
                    gadget = ""
                    for decode in ldecodes:
                        gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                    if len(gadget) > 0:
                        gadget = gadget[:-3]
                        if (startAddress % gad[C_ALIGN]) == 0:
                            onegad = {}
                            onegad["address"] = startAddress
                            onegad["gad_instr"] = ldecodes
                            onegad["gadget"] = gadget
                            onegad["bytes"] = section.data()[ref - (i*gad[C_ALIGN]):ref+gad[C_SIZE]]
                            if self.need_filter:
                                allgadgets += self.__filter_for_big_binary_or_elf32(onegad)
                            else:
                                allgadgets += [onegad]

        return allgadgets

    def __filter_for_big_binary_or_elf32(self, gadgets):
        '''Filter gadgets for big binary.
        '''
        new = []
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
            [pop,add,ret,leave,mov,xchg,int80,syscall,sysenter]))

        insns = [g.strip() for g in gadgets["gadget"].split(";")]
        if all(map(valid, insns)):
            new.append(gadgets)

        return new

    def __checkInstructionBlackListedX86(self, insts):
        bl = ["db", "int3", "call", "jmp", "nop", "jne", "jg", "jge"]
        for inst in insts:
            for b in bl:
                if inst.split(" ")[0] == b:
                    return True 
        return False

    def __checkMultiBr(self, insts, br):
        count = 0
        for inst in insts:
            if inst.split()[0] in br:
                count += 1
        return count

    def __passCleanX86(self, gadgets, multibr=False):
        new = []
        # Only extract "ret" gadgets now.
        if self.gadget_filter == "all":
            br = ["ret", "int", "sysenter", "jmp", "call"]
        else:
            br = [self.gadget_filter]

        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if self.__checkInstructionBlackListedX86(insts):
                continue
            if not multibr and self.__checkMultiBr(insts, br) > 1:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new
    
    def __deduplicate(self, gadgets):
        new, insts = [], []
        for gadget in gadgets:
            if gadget["gadget"] in insts:
                continue
            insts.append(gadget["gadget"])
            new += [gadget]
        return new

    def __get_cachefile_name(self, elf):
        basename = os.path.basename(elf.file.name)
        sha256   = hashlib.sha256(elf.get_data()).hexdigest()
        cachedir  = os.path.join(tempfile.gettempdir(), 'binjitsu-rop-cache')

        if not os.path.exists(cachedir):
            os.mkdir(cachedir)

        return os.path.join(cachedir, sha256)

    def __cache_load(self, elf):
        filename = self.__get_cachefile_name(elf)

        if not os.path.exists(filename):
            return None

        log.info_once("Loaded cached gadgets for %r" % elf.file.name)
        gadgets = eval(file(filename).read())

        # Gadgets are saved with their 'original' load addresses.
        gadgets = {k-elf.load_addr+elf.address:v for k,v in gadgets.items()}

        return gadgets

    def __cache_save(self, elf, data):
        # Gadgets need to be saved with their 'original' load addresses.
        data = {k+elf.load_addr-elf.address:v for k,v in data.items()}

        file(self.__get_cachefile_name(elf),'w+').write(repr(data))

