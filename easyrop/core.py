import re

from easyrop.binary import Binary
from easyrop.util.parser import Parser

from capstone import *
from capstone.x86 import *


class Core:
    def __init__(self, options):
        self.__options = options
        self.__gadgets = []

    def analyze(self):
        binary = Binary(self.__options)
        # search for gadgets
        self.__gadgets += self.addROPGadgets(binary)
        self.__gadgets += self.addJOPGadgets(binary)
        # apply some options
        if not self.__options.all:
            self.__gadgets = self.__deleteDuplicateGadgets(self.__gadgets)
        self.__gadgets = self.__passClean(self.__gadgets)
        # print
        if self.__options.op:
            gadgets = self.__searchOperation(binary, self.__options.op, self.__options.reg_src, self.__options.reg_dst)
            gadgets = self.__deleteDuplicateGadgets(gadgets)
            self.__printGadgets(gadgets)
        else:
            self.__printGadgets(self.__gadgets)

    def addROPGadgets(self, binary):
        gadgets = [
            [b"\xc3", 1],                # ret
            [b"\xc2[\x00-\xff]{2}", 3],  # ret <imm>
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
        arch = binary.getArch()
        mode = binary.getArchMode()
        md = Cs(arch, mode)
        md.detail = True

        parser = Parser(op)
        operation = parser.parse()
        ret = []
        # TODO generate ropchains that constitutes an operation
        if (src is None) or (dst is None):
            sets = operation.getSets()
            for gadget in self.__gadgets:
                for s in sets:
                    _dst = dst
                    _src = src
                    decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                    auxSet = copy.deepcopy(s)
                    for decode, ins in zip(decodes, s.getInstructions()):
                        if not decode.mnemonic == ins.getMnemonic():
                            break
                        if len(decode.operands) > 0:
                            if _dst is None and ins.getReg1() == 'dst':
                                _dst = self.__getRegister(decode, 0)
                            elif _dst is None and ins.getReg2() == 'dst':
                                _dst = self.__getRegister(decode, 1)
                            if _src and ins.getReg1() == 'src':
                                _src = self.__getRegister(decode, 0)
                            elif _src is None and ins.getReg2() == 'src':
                                _src = self.__getRegister(decode, 1)
                            auxSet.setSrc(_src)
                            auxSet.setDst(_dst)
                    else:
                        toSearch = str(auxSet)
                        searched = re.match(toSearch, gadget["gadget"])
                        if searched:
                            ret += [gadget]
        else:
            operation.setDst(dst)
            operation.setSrc(src)
            sets = operation.getSets()
            for s in sets:
                toSearch = str(s)
                for gadget in self.__gadgets:
                    gad = gadget["gadget"]
                    searched = re.match(toSearch, gad)
                    if searched:
                        ret += [gadget]
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
        br = ["ret", "retf", "jmp", "call"]
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
