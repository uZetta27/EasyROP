import re

from easyrop.operations.instruction_exception import InstructionException

DESTINATION = "dst"
SOURCE = "src"
AUXILIARY = "aux"

class Instruction:
    def __init__(self, mnemonic, reg1='', reg2='', value1='', value2=''):
        self._mnemonic = mnemonic
        self._reg1 = reg1
        self._reg2 = reg2
        self._value1 = value1.upper().replace('X', 'x')
        self._value2 = value2.upper().replace('X', 'x')
        self.check_fields()

    def get_mnemonic(self):
        return self._mnemonic

    def check_fields(self):
        self.check_value(self._value1)
        self.check_value(self._value2)

    def check_value(self, value):
        if value:
            if re.search(r"^0x[0-9A-F]{1,16}$", value) is None:
                raise InstructionException("Bad hex value '%s'" % value)

    def set_aux(self, aux):
        if AUXILIARY in self._reg1:
            self._reg1 = self._reg1.replace(AUXILIARY, aux)
        if AUXILIARY in self._reg2:
            self._reg2 = self._reg2.replace(AUXILIARY, aux)

    def need_value1(self):
        return self._value1 != ""

    def get_value1(self):
        return self._value1

    def get_reg1(self):
        return self._reg1.replace('[', '').replace(']', '')

    def is_reg1_dst(self):
        return DESTINATION in self._reg1

    def is_reg1_src(self):
        return SOURCE in self._reg1

    def is_reg1_aux(self):
        return AUXILIARY in self._reg1

    def is_reg1_address(self):
        return re.search(r"^\[.+\]$", self._reg1) != None

    def need_value2(self):
        return self._value2 != ""

    def get_value2(self):
        return self._value2

    def get_reg2(self):
        return self._reg2.replace('[', '').replace(']', '')

    def is_reg2_dst(self):
        return DESTINATION in self._reg2

    def is_reg2_src(self):
        return SOURCE in self._reg2

    def is_reg2_aux(self):
        return AUXILIARY in self._reg2

    def is_reg2_address(self):
        return re.search(r"^\[.+\]$", self._reg2) != None

    def set_dst(self, dst):
        if DESTINATION in self._reg1:
            self._reg1 = self._reg1.replace(DESTINATION, dst)
        if DESTINATION in self._reg2:
            self._reg2 = self._reg2.replace(DESTINATION, dst)

    def set_src(self, src):
        if SOURCE in self._reg1:
            self._reg1 = self._reg1.replace(SOURCE, src)
        if SOURCE in self._reg2:
            self._reg2 = self._reg2.replace(SOURCE, src)

    def __str__(self):
        return ('%s %s (%s) %s (%s)' % (self._mnemonic, self._reg1, self._value1, self._reg2, self._value2)).replace(' ()', '').replace('  ', ' ')
