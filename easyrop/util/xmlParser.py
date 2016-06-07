import xml.etree.ElementTree

from easyrop.operation import Operation
from easyrop.gadget import Gadget
from easyrop.instruction import Instruction


class XmlParser:
    def __init__(self, options, path):
        self.__file = xml.etree.ElementTree.parse(path).getroot()
        self.__options = options

    def parse(self):
        __operation = Operation(self.__options.op)
        for operation in self.__file.findall('operation'):
            if operation.get('name') == self.__options.op:
                for gadget in operation.iter('gadget'):
                    size = gadget.get('size')
                    g = Gadget(size)
                    for ins in gadget.iter('ins'):
                        i = Instruction(ins.get('mnemonic'), ins.find('src'), ins.find('dest'))
                        g.addIntruction(i)
                    __operation.addGadget(g)
        return __operation
