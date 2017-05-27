"""
Interface to implement to parse different binary formats (PE, Mach-O, ELF, etc.)
"""

import sys
from easyrop.binaries.pe import Pe


class Binary:
    def __init__(self, binary):
        self.__file_name = binary
        self.__binary = None

        try:
            self.__binary = Pe(self.__file_name)
        except IOError:
            print("[Error] Can't open binary or binary not found")
            sys.exit(-1)

    def get_file_name(self):
        return self.__file_name

    def get_binary(self):
        return self.__binary

    def get_entry_point(self):
        return self.__binary.get_entry_point()

    def get_exec_sections(self):
        return self.__binary.get_exec_sections()

    def get_arch(self):
        return self.__binary.get_arch()

    def get_arch_mode(self):
        return self.__binary.get_arch_mode()
