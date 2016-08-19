import xml.etree.ElementTree
import os

from easyrop.operation import Operation
from easyrop.set import Set
from easyrop.instruction import Instruction


class XmlParser:
    def __init__(self, op):
        path = os.getcwd() + '\easyrop\gadgets\\turingOP.xml'
        self.__file = xml.etree.ElementTree.parse(path).getroot()
        self.__op = op

    def parse(self):
        __operation = Operation(self.__op)
        for operation in self.__file.findall('operation'):
            if operation.get('name') == self.__op:
                for set in operation.iter('set'):
                    s = Set()
                    for ins in set.iter('ins'):
                        reg1 = ins.find('reg1')
                        reg1_name = ''
                        reg2 = ins.find('reg2')
                        reg2_name = ''
                        if reg1 is not None:
                            reg1_name = reg1.text
                        if reg2 is not None:
                            reg2_name = reg2.text
                        i = Instruction(ins.get('mnemonic'), reg1_name, reg2_name)
                        s.addIntruction(i)
                    __operation.addSet(s)
        return __operation
