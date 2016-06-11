import os
import re

from easyrop.binary import Binary
from easyrop.util.parser import Parser

from capstone import *
from capstone.x86_const import *


class Core:
    def __init__(self, options):
        self.__options = options
        self.__gadgets = []

    def analyze(self):
        path = os.getcwd() + '\easyrop\gadgets\\turingOP.xml'
        parser = Parser(self.__options, path)
        operations = parser.parse()
        binary = Binary(self.__options)
        self.addROPGadgets(binary, operations)
        self.printGadgets()

    def addROPGadgets(self, binary, operations):
        gadgets = [
            [b"\xc3", 1],                # ret
            [b"\xc2[\x00-\xff]{2}", 3],  # ret <imm>
            [b"\xcb", 1],                # retf
            [b"\xca[\x00-\xff]{2}", 3]   # retf <imm>
        ]

        if len(gadgets) > 0:
            self.__gadgets += self.__searchGadgets(binary, gadgets, operations)

    def __searchGadgets(self, binary, gadgets, operations):
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
                        if decodes:
                            gadget = ""
                            for decode in decodes:
                                gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                            if len(gadget) > 0:
                                ret += [{"vaddr": vaddr + ref - depth, "gadget": gadget, "bytes": section[ref - depth:ref + gad[C_SIZE]]}]
        return ret

    def printGadgets(self):
        print("All information gadgets")
        print("============================================")
        if self.__options.all:
            gadgets = self.__gadgets
        else:
            gadgets = self.__deleteDuplicateGadgets()
        gadgets = self.__alphaSortgadgets(gadgets)

        for gad in gadgets:
            print("0x%x : %s" % (gad["vaddr"], gad["gadget"]))
        print("\nGadgets found: %d" % len(gadgets))

    def __deleteDuplicateGadgets(self):
        gadgets_content_set = set()
        unique_gadgets = []
        for gadget in self.__gadgets:
            gad = gadget["gadget"]
            if gad in gadgets_content_set:
                continue
            gadgets_content_set.add(gad)
            unique_gadgets += [gadget]
        return unique_gadgets

    def __alphaSortgadgets(self, currentGadgets):
        return sorted(currentGadgets, key=lambda key: key["gadget"])
