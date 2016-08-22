DESTINATION = 'dst'
SOURCE = 'src'
AUXILIARY = 'aux'
DESTINATION_ADDRESS = '[dst]'
SOURCE_ADDRESS = '[src]'

REG1 = 0
REG2 = 1


class Instruction:
    def __init__(self, mnemonic, reg1='', reg2='', value1='', value2=''):
        self.__registers = [reg1, reg2]
        self.__values = [value1, value2]
        self.__address = [False, False]
        if (reg1 == DESTINATION_ADDRESS) or (reg1 == SOURCE_ADDRESS):
            self.__address[REG1] = True
        if ('[' in reg1) and not ((reg1 == DESTINATION_ADDRESS) or (reg1 == SOURCE_ADDRESS)):
            reg1 = reg1.replace("[", "")
            reg1 = reg1.replace("]", "")
            self.__address[REG1] = True
            self.__registers[REG1] = reg1
        if (reg2 == DESTINATION_ADDRESS) or (reg2 == SOURCE_ADDRESS) or ('[' in reg2):
            self.__address[REG2] = True
        if ('[' in reg2) and not ((reg2 == DESTINATION_ADDRESS) or (reg2 == SOURCE_ADDRESS)):
            reg2 = reg2.replace("[", "")
            reg2 = reg2.replace("]", "")
            self.__address[REG2] = True
            self.__registers[REG2] = reg2
        self.__mnemonic = mnemonic

    def there_is_reg(self, reg):
        if (reg >= 0) and (reg < len(self.__registers)):
            return len(self.__registers[reg]) != 0
        return False

    def set_dst(self, dst):
        self.set_type(DESTINATION, dst)

    def set_src(self, src):
        self.set_type(SOURCE, src)

    def set_aux(self, aux):
        self.set_type(AUXILIARY, aux)

    def set_dst_address(self, address):
        self.set_type(DESTINATION_ADDRESS, address)

    def set_src_address(self, address):
        self.set_type(SOURCE_ADDRESS, address)

    def set_type(self, reg_type, value):
        if self.__registers[REG1] == reg_type:
            self.__registers[REG1] = value
        if self.__registers[REG2] == reg_type:
            self.__registers[REG2] = value

    def need_aux(self):
        return (self.__registers[REG1] or self.__registers[REG2]) == AUXILIARY

    def is_dst(self, reg):
        if (reg >= 0) and (reg < len(self.__registers)):
            return self.__registers[reg] == DESTINATION
        return False

    def is_src(self, reg):
        if (reg >= 0) and (reg < len(self.__registers)):
            return self.__registers[reg] == SOURCE
        return False

    def is_aux(self, reg):
        if (reg >= 0) and (reg < len(self.__registers)):
            return self.__registers[reg] == AUXILIARY
        return False

    def is_address(self, reg):
        if (reg >= 0) and (reg < len(self.__address)):
            return self.__address[reg]
        return False

    def need_value(self, reg):
        if (reg >= 0) and (reg < len(self.__values)):
            return len(self.__values[reg]) != 0
        return False

    def get_value(self, reg):
        if (reg >= 0) and (reg < len(self.__values)):
            if self.need_value(reg):
                return ' (' + self.__registers[reg] + ' = ' + self.__values[reg] + ')'
        return ''

    def get_register(self, reg):
        if (reg >= 0) and (reg < len(self.__registers)):
            return self.__registers[reg]
        return None

    def get_mnemonic(self):
        return self.__mnemonic

    def __str__(self):
        string = ''
        if len(self.__registers[REG1]) != 0 and len(self.__registers[REG2]) != 0:
            string = str(self.__mnemonic) + ' ' + str(self.__registers[REG1]) + ', ' + str(self.__registers[REG2])
        elif len(self.__registers[REG1]) != 0 and len(self.__registers[REG2]) == 0:
            string = str(self.__mnemonic) + ' ' + str(self.__registers[REG1])
        elif len(self.__registers[REG1]) == 0:
            string = str(self.__mnemonic)
        return string
