from pefile import *
from capstone import *


class Pe:
    def __init__(self, file_name):
        self.__file_name = file_name
        self.__pe = None
        self.__archMode = None
        self.__arch = None

        self.__pe = PE(file_name)

        self.parse_arch()

    def parse_arch(self):
        if hex(self.__pe.FILE_HEADER.Machine) == '0x14c':
            self.__archMode = CS_MODE_32
            self.__arch = CS_ARCH_X86
        elif hex(self.__pe.FILE_HEADER.Machine) == '0x8664':
            self.__archMode = CS_MODE_64
            self.__arch = CS_ARCH_X86

    def get_file_name(self):
        return self.__file_name

    def get_binary(self):
        return self.__pe

    def get_entry_point(self):
        return self.__pe.OPTIONAL_HEADER.ImageBase + self.__pe.OPTIONAL_HEADER.BaseOfCode

    def get_exec_sections(self):
        return self.__pe.sections[0].get_data()

    def get_arch(self):
        return self.__arch

    def get_arch_mode(self):
        return self.__archMode
