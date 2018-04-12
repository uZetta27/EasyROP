"""
Interface to implement to parse different sources of gadgets
"""
import __main__
import os

from easyrop.parsers.parse_exception import ParseException
from easyrop.parsers.xml_parser import XmlParser

class Parser:
    def __init__(self):
        self._file = XmlParser()

    def get_all_ops(self):
        return self._file.get_all_ops()

    def get_operation(self, op):
        try:
            return self._file.get_operation(op)
        except ParseException:
            ops = self._file.get_all_ops()
            ops.sort()
            string = ", ".join(ops)
            print("%s: '%s': Can not find op between: %s" % (os.path.basename(__main__.__file__), op, string))
            raise
