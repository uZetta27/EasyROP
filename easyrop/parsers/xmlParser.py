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
REGISTER_1 = 'reg1'
REGISTER_2 = 'reg2'
MNEMONIC = 'mnemonic'


class XmlParser:
    def __getAllFiles(self):
        return [f for f in listdir(os.getcwd() + GADGET_DIRECTORY) if isfile(join(os.getcwd() + GADGET_DIRECTORY, f))]

    def __init__(self, op):
        self.__op = op
        self.__files = self.__getAllFiles()
        found = False
        i = 0
        while i < len(self.__files) and not found:
            path = os.getcwd() + GADGET_DIRECTORY + '\\' + self.__files[i]
            self.__file = xml.etree.ElementTree.parse(path).getroot()
            for operation in self.__file.findall(OPERATION):
                if op == operation.get(NAME):
                    found = True
            i += 1

    def getAllOps(self):
        ops = []
        for file in self.__files:
            path = os.getcwd() + GADGET_DIRECTORY + '\\' + file
            f = xml.etree.ElementTree.parse(path).getroot()
            for operation in f.findall(OPERATION):
                ops += [operation.get(NAME)]
        return ops

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
