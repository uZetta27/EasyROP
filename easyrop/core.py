import os
import re

from easyrop.binary import Binary
from easyrop.util.parser import Parser

from capstone import *
from capstone.x86_const import *


class Core:
    def __init__(self, options):
        self.__options = options

    def analyze(self):
        path = os.getcwd() + '\easyrop\gadgets\\turingOP.xml'
        parser = Parser(self.__options, path)
        operations = parser.parse()
        binary = Binary(self.__options)
        self.addROPGadgets(binary, operations)

    def addROPGadgets(self, binary, operations):
        gadgets = [
            [b"\xc3", 1, 1],                # ret
            [b"\xc2[\x00-\xff]{2}", 3, 1],  # ret <imm>
            [b"\xcb", 1, 1],                # retf
            [b"\xca[\x00-\xff]{2}", 3, 1]   # retf <imm>
        ]

        if len(gadgets) > 0:
            self.__searchGadgets(binary, gadgets, operations)

    def __searchGadgets(self, binary, gadgets, operations):
        section = binary.getExecSections()
        vaddr = binary.getEntryPoint()
        arch = binary.getArch()
        mode = binary.getArchMode()

        C_OP = 0
        C_SIZE = 1
        C_ALIGN = 2

        md = Cs(arch, mode)
        count = 0
        for gad in gadgets:
            allRefRet = [m.start() for m in re.finditer(gad[C_OP], section)]
            for ref in allRefRet:
                decodes = md.disasm(section[ref - self.__options.depth:ref + gad[C_SIZE]], vaddr + ref - self.__options.depth)
                if decodes:
                    count += 1
                    print('0x%x: ' % (vaddr + ref - self.__options.depth), end='')
                    for decode in decodes:
                        print("%s %s" % (decode.mnemonic, decode.op_str), end='; ')
                    print()
        print('\nGadgets found: %s' % count)
