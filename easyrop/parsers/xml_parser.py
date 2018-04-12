import __main__
import os

import xml.etree.ElementTree
from xml.etree.ElementTree import ParseError
from easyrop.parsers.parse_exception import ParseException

from easyrop.operations.operation import Operation
from easyrop.operations.set import Set
from easyrop.operations.instruction import Instruction

GADGET_DIRECTORY = os.path.realpath(os.path.join(os.path.dirname(__main__.__file__), "easyrop", "gadgets"))

OPERATION = 'operation'
SET = 'set'
INSTRUCTION = 'ins'
NAME = 'name'
MNEMONIC = 'mnemonic'
REG1 = 'reg1'
REG2 = 'reg2'
VALUE = 'value'

class XmlParser:
    def __init__(self):
        self._files = self.get_all_files()

    def get_all_files(self):
        return [os.path.join(GADGET_DIRECTORY, f) for f in os.listdir(GADGET_DIRECTORY) if os.path.isfile(os.path.join(GADGET_DIRECTORY, f))]

    def get_all_ops(self):
        ops = []
        for file in self._files:
            f = xml.etree.ElementTree.parse(file).getroot()
            for operation in f.findall(OPERATION):
                ops += [operation.get(NAME)]
        return ops

    def get_operation(self, op):
        file = self.get_file(op)
        operation = Operation(op)
        for match in file.findall(OPERATION):
            if op == match.get(NAME):
                for set_ in match.iter(SET):
                    s = Set()
                    for ins in set_.iter(INSTRUCTION):
                        reg1, value1 = self.get_value(ins, REG1)
                        reg2, value2 = self.get_value(ins, REG2)
                        i = Instruction(ins.get(MNEMONIC), reg1, reg2, value1, value2)
                        s.add_instruction(i)
                    operation.add_set(s)
        return operation

    def get_value(self, ins, reg):
        try:
            r = ins.find(reg).text
            value = ins.find(reg).get(VALUE)
            if value is None:
                value = ''
        except AttributeError:
            r = ''
            value = ''

        return r, value

    def get_file(self, op):
        for path_file in self._files:
            file = xml.etree.ElementTree.parse(path_file).getroot()
            for operation in file.findall(OPERATION):
                if op == operation.get(NAME):
                    return file

        raise ParseException
