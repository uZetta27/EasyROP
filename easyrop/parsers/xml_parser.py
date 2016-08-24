import xml.etree.ElementTree
import os

from os import listdir
from os.path import isfile, join

from easyrop.operation import Operation
from easyrop.set import Set
from easyrop.instruction import Instruction

GADGET_DIRECTORY = '\easyrop\gadgets'

OPERATION = 'operation'
NAME = 'name'
SET = 'set'
INSTRUCTION = 'ins'
REG1 = 'reg1'
REG2 = 'reg2'
MNEMONIC = 'mnemonic'
VALUE = 'value'


class XmlParser:
    def get_all_files(self):
        return [f for f in listdir(os.getcwd() + GADGET_DIRECTORY) if isfile(join(os.getcwd() + GADGET_DIRECTORY, f))]

    def __init__(self, op):
        self.__op = op
        self.__files = self.get_all_files()
        self.__file = self.get_file(op)

    def get_file(self, op):
        found = False
        i = 0
        file = None
        while i < len(self.__files) and not found:
            path = os.getcwd() + GADGET_DIRECTORY + '\\' + self.__files[i]
            file = xml.etree.ElementTree.parse(path).getroot()
            for operation in file.findall(OPERATION):
                if op == operation.get(NAME):
                    found = True
            i += 1
        return file

    def get_all_ops(self):
        ops = []
        for file in self.__files:
            path = os.getcwd() + GADGET_DIRECTORY + '\\' + file
            f = xml.etree.ElementTree.parse(path).getroot()
            for operation in f.findall(OPERATION):
                ops += [operation.get(NAME)]
        return ops

    def get_operation(self):
        __operation = Operation(self.__op)
        for operation in self.__file.findall(OPERATION):
            if operation.get(NAME) == self.__op:
                for set_ in operation.iter(SET):
                    s = Set()
                    for ins in set_.iter(INSTRUCTION):
                        reg1 = ins.find(REG1)
                        reg1_name = ''
                        value1 = ''
                        reg2 = ins.find(REG2)
                        reg2_name = ''
                        value2 = ''
                        if reg1 is not None:
                            reg1_name = reg1.text
                            if reg1.get(VALUE) is not None:
                                value1 = reg1.get(VALUE)
                        if reg2 is not None:
                            reg2_name = reg2.text
                            if reg2.get(VALUE) is not None:
                                value2 = reg2.get(VALUE)
                        i = Instruction(ins.get(MNEMONIC), reg1_name, reg2_name, value1, value2)
                        s.add_instruction(i)
                    __operation.add_set(s)
        return __operation
