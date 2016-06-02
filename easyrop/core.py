import cmd
import os

from easyrop.binary import Binary
from easyrop.util.parser import Parser
from capstone import *


class Core(cmd.Cmd):
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary = None

    def analyze(self):
        parser = Parser(os.getcwd() + '\easyrop\gadgets\\turingOP.xml')
        parser.parse()
        self.__binary = Binary(self.__options)
        md = Cs(self.__binary.getArch(), self.__binary.getArchMode())
        for i in md.disasm(self.__binary.getExecSections(), self.__binary.getEntryPoint()):
            if i.id == self.__options.op:
                print('0x%x:\t%s\t%s (%x bytes)' % (i.address, i.mnemonic, i.op_str, i.size))
