from pefile import *
from capstone import *

X86_MAGIC_NUMBER = 0x14c
X64_MAGIC_NUMBER = 0x8664

class Pe:
    def __init__(self, file_name):
        self._file_name = file_name
        self._pe = PE(file_name)
        self._arch_mode = None
        self._arch = None
        self.parse_arch()

    def parse_arch(self):
        if self._pe.FILE_HEADER.Machine == X86_MAGIC_NUMBER:
            self._arch_mode = CS_MODE_32
            self._arch = CS_ARCH_X86
        elif self._pe.FILE_HEADER.Machine == X64_MAGIC_NUMBER:
            self._arch_mode = CS_MODE_64
            self._arch = CS_ARCH_X86

    def get_file_name(self):
        return self._file_name

    def get_entry_point(self):
        return self._pe.OPTIONAL_HEADER.ImageBase + self._pe.OPTIONAL_HEADER.BaseOfCode

    def get_exec_sections(self):
        return self._pe.sections[0].get_data()

    def get_arch(self):
        return self._arch

    def get_arch_mode(self):
        return self._arch_mode
