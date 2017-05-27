"""
Interface to implement to parse different sources of gadgets
"""

from easyrop.parsers.parse_exception import ParseException
from easyrop.parsers.xml_parser import XmlParser


class Parser:
    def __init__(self, op):
        self.__file = None

        try:
            self.__file = XmlParser(op)
        except ParseException:
            raise

    def get_all_ops(self):
        return self.__file.get_all_ops()

    def get_operation(self):
        return self.__file.get_operation()
