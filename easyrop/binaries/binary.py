import os
import __main__

from easyrop.binaries.pe import Pe
from easyrop.binaries.binary_exception import BinaryException

from pefile import PEFormatError

class Binary:
    def __init__(self, file_name):
        try:
            self._binary = Pe(file_name)
        except PEFormatError:
            print("%s: '%s': Not a PE file" % (os.path.basename(__main__.__file__), os.path.realpath(file_name)))
            raise BinaryException

    def get_file_name(self):
        return self._binary.get_file_name()

    def get_entry_point(self):
        return self._binary.get_entry_point()

    def get_exec_sections(self):
        return self._binary.get_exec_sections()

    def get_arch(self):
        return self._binary.get_arch()

    def get_arch_mode(self):
        return self._binary.get_arch_mode()
