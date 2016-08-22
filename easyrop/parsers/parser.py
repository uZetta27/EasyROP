import sys

from easyrop.parsers.xml_parser import XmlParser


class Parser:
    def __init__(self, op):
        self.__file = None

        try:
            self.__file = XmlParser(op)
        except:
            print("[Error] Can't read form gadget source")
            sys.exit(-1)

    def get_all_ops(self):
        return self.__file.get_all_ops()

    def get_operation(self):
        return self.__file.get_operation()
