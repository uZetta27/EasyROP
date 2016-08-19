import xml.etree.ElementTree
import os

from easyrop.operation import Operation
from easyrop.set import Set
from easyrop.instruction import Instruction

TURING_XML = '\easyrop\gadgets\\turingOP.xml'

OPERATION = 'operation'
NAME = 'name'
SET = 'set'
INSTRUCTION = 'ins'
REGISTER_1 = 'reg1'
REGISTER_2 = 'reg2'
MNEMONIC = 'mnemonic'

class XmlParser:
    def __init__(self, op):
        path = os.getcwd() + TURING_XML
        self.__file = xml.etree.ElementTree.parse(path).getroot()
        self.__op = op

    def parse(self):
        __operation = Operation(self.__op)
        for operation in self.__file.findall(OPERATION):
            if operation.get(NAME) == self.__op:
                for set in operation.iter(SET):
                    s = Set()
                    for ins in set.iter(INSTRUCTION):
                        reg1 = ins.find(REGISTER_1)
                        reg1_name = ''
                        reg2 = ins.find(REGISTER_2)
                        reg2_name = ''
                        if reg1 is not None:
                            reg1_name = reg1.text
                        if reg2 is not None:
                            reg2_name = reg2.text
                        i = Instruction(ins.get(MNEMONIC), reg1_name, reg2_name)
                        s.addIntruction(i)
                    __operation.addSet(s)
        return __operation
