import cmd
import os

from easyrop.binary import Binary
from easyrop.util.parser import Parser

from capstone import *
from capstone.x86_const import *


class Core(cmd.Cmd):
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options

    def analyze(self):
        __path = os.getcwd() + '\easyrop\gadgets\\turingOP.xml'
        parser = Parser(self.__options, __path)
        __operations = parser.parse()
        __binary = Binary(self.__options)
        self.__searchGadgets(__binary, __operations)

    def __searchGadgets(self, binary, operations):
        print(str(operations))
        md = Cs(binary.getArch(), binary.getArchMode())
        for i in md.disasm(binary.getExecSections(), binary.getEntryPoint()):
            if i.id == '':
                print('0x%x:\t%s\t%s (%x bytes)' % (i.address, i.mnemonic, i.op_str, i.size))
