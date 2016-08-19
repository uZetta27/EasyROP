import datetime
import re

from capstone import *
from capstone.x86 import *

from easyrop.binaries.binary import Binary
from easyrop.parsers.parser import Parser


class Core:
    def __init__(self, options):
        self.__options = options
        self.__gadgets = []

    def analyze(self):
        start = datetime.datetime.now()
        binary = Binary(self.__options)
        # search for gadgets
        self.__gadgets += self.addROPGadgets(binary)
        if not self.__options.nojop:
            self.__gadgets += self.addJOPGadgets(binary)
        # apply some options
        if not self.__options.all:
            self.__gadgets = self.__deleteDuplicateGadgets(self.__gadgets)
        self.__gadgets = self.__passClean(self.__gadgets)
        # print
        if self.__options.op:
            if self.__options.ropchain:
                ropchains = self.__searchRopchains(binary, self.__options.op, self.__options.reg_src, self.__options.reg_dst)
                self.__printRopchains(ropchains)
            else:
                gadgets = self.__searchOperation(binary, self.__options.op, self.__options.reg_src, self.__options.reg_dst)
                self.__printGadgets(gadgets)
        else:
            self.__printGadgets(self.__gadgets)
        end = datetime.datetime.now() - start
        # print time
        print('\nTime elapsed: %s' % str(end))

    def addROPGadgets(self, binary):
        gadgets = [
            [b"\xc3", 1],               # ret
            [b"\xc2[\x00-\xff]{2}", 3]  # ret <imm>
        ]
        if not self.__options.noretf:
            gadgets += [
                [b"\xcb", 1],                # retf
                [b"\xca[\x00-\xff]{2}", 3]   # retf <imm>
            ]

        return self.__searchGadgets(binary, gadgets)

    def addJOPGadgets(self, binary):
        gadgets = [
            [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2],      # jmp  [reg]
            [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2],  # jmp  [reg]
            [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2],      # jmp  [reg]
            [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2]   # call [reg]
        ]

        return self.__searchGadgets(binary, gadgets)

    def __searchGadgets(self, binary, gadgets):
        section = binary.getExecSections()
        vaddr = binary.getEntryPoint()
        arch = binary.getArch()
        mode = binary.getArchMode()

        C_OP = 0
        C_SIZE = 1

        ret = []
        md = Cs(arch, mode)
        for gad in gadgets:
            allRefRet = [m.start() for m in re.finditer(gad[C_OP], section)]
            for ref in allRefRet:
                for depth in range(self.__options.depth):
                        decodes = md.disasm(section[ref - depth:ref + gad[C_SIZE]], vaddr + ref - depth)
                        gadget = ""
                        for decode in decodes:
                            gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                        if len(gadget) > 0:
                            gadget = gadget[:-3]
                            ret += [{"vaddr": vaddr + ref - depth, "gadget": gadget, "bytes": section[ref - depth:ref + gad[C_SIZE]]}]
        return ret

    def __searchOperation(self, binary, op, src, dst):
        parser = Parser(op)
        ret = []
        arch = binary.getArch()
        mode = binary.getArchMode()
        if not (src and dst):
            md = Cs(arch, mode)
            md.detail = True
            for gadget in self.__gadgets:
                operation = parser.parse()
                sets = operation.getSets()
                for s in sets:
                    _dst = dst
                    _src = src
                    decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                    for decode, ins in zip(decodes, s.getInstructions()):
                        if decode.mnemonic == ins.getMnemonic():
                            if len(decode.operands) > 0:
                                if not _dst:
                                    if ins.isReg1Dst():
                                        _dst = self.__getRegister(decode, 0)
                                    elif ins.isReg2Dst():
                                        _dst = self.__getRegister(decode, 1)
                                if not _src:
                                    if ins.isReg1Src():
                                        _src = self.__getRegister(decode, 0)
                                    elif ins.isReg2Src():
                                        _src = self.__getRegister(decode, 1)
                        else:
                            break
                    else:
                        s.setDst(_dst)
                        s.setSrc(_src)
                        toSearch = str(s)
                        searched = re.match(toSearch, gadget["gadget"])
                        if searched:
                            ret += [gadget]
        else:
            operation = parser.parse()
            operation.setDst(dst)
            operation.setSrc(src)
            sets = operation.getSets()
            md = Cs(arch, mode)
            md.detail = True
            for s in sets:
                if s.needAux():
                    for gadget in self.__gadgets:
                        _aux = None
                        decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                        for decode, ins in zip(decodes, s.getInstructions()):
                            if decode.mnemonic == ins.getMnemonic():
                                if len(decode.operands) > 0:
                                    if not _aux:
                                        if ins.isReg1Aux():
                                            _aux = self.__getRegister(decode, 0)
                                        elif ins.isReg2Aux():
                                            _aux = self.__getRegister(decode, 1)
                            else:
                                break
                        else:
                            s.setAux(_aux)
                            toSearch = str(s)
                            searched = re.match(toSearch, gadget["gadget"])
                            if searched:
                                ret += [gadget]
                else:
                    toSearch = str(s)
                    for gadget in self.__gadgets:
                        gad = gadget["gadget"]
                        searched = re.match(toSearch, gad)
                        if searched:
                            ret += [gadget]
        return ret

    def __searchRopchains(self, binary, op, src, dst):
        parser = Parser(op)
        ret = []
        if not (src and dst):
            print('Not supported: src and dst needed')
        else:
            operation = parser.parse()
            operation.setDst(dst)
            operation.setSrc(src)
            sets = operation.getSets()
            for s in sets:
                chain = []
                if len(s) > 1:
                    for ins in s.getInstructions():
                        for gadget in self.__gadgets:
                            toSearch = str(ins)
                            gad = gadget["gadget"]
                            searched = re.match(toSearch, gad)
                            if searched and gadget not in chain:
                                chain += [gadget]
                                break
                        if len(s) == len(chain):
                            ret += [chain]
        return ret

    def __getRegister(self, decode, position):
        reg = None
        if position < len(decode.operands):
            i = decode.operands[position]
            if i.type == X86_OP_REG:
                reg = decode.reg_name(i.reg)
            if i.type == X86_OP_MEM:
                if i.mem.base != 0:
                    reg = decode.reg_name(i.mem.base)
        return reg

    def __printGadgets(self, gadgets):
        print("Gadgets information")
        print("============================================================")
        gadgets = self.__alphaSortgadgets(gadgets)
        for gad in gadgets:
            print("0x%x : %s" % (gad["vaddr"], gad["gadget"]))
        print("\nGadgets found: %d" % len(gadgets))

    def __printRopchains(self, ropchains):
        print("ROPchains information")
        print("============================================================")
        for chain in ropchains:
            for gad in chain:
                print("0x%x : %s" % (gad["vaddr"], gad["gadget"]))
            print('-----------------------------------------')
        print("\nROPchains found: %d" % len(ropchains))

    def __deleteDuplicateGadgets(self, gadgets):
        gadgets_content_set = set()
        unique_gadgets = []
        for gadget in gadgets:
            gad = gadget["gadget"]
            if gad in gadgets_content_set:
                continue
            gadgets_content_set.add(gad)
            unique_gadgets += [gadget]
        return unique_gadgets

    def __alphaSortgadgets(self, currentGadgets):
        return sorted(currentGadgets, key=lambda key: key["gadget"])

    def __passClean(self, gadgets):
        new = []
        br = ["ret"]
        if not self.__options.noretf:
            br += ["retf"]
        if not self.__options.nojop:
            br += ["jmp", "call"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new
