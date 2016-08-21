DESTINATION = 'dst'
SOURCE = 'src'
AUXILIARY = 'aux'
DESTINATION_ADDRESS = '[dst]'
SOURCE_ADDRESS = '[src]'


class Instruction:
    def __init__(self, mnemonic, reg1, reg2):
        self.__mnemonic = mnemonic
        self.__reg1 = reg1
        self.__reg2 = reg2

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
        if self.__reg1 == reg_type:
            self.__reg1 = value
        if self.__reg2 == reg_type:
            self.__reg2 = value

    def need_aux(self):
        return (self.__reg1 or self.__reg2) == AUXILIARY

    def need_address(self):
        return (self.__reg1 or self.__reg2) == (SOURCE_ADDRESS or DESTINATION_ADDRESS)

    def is_reg1_dst(self):
        return self.__reg1 == DESTINATION

    def is_reg2_dst(self):
        return self.__reg2 == DESTINATION

    def is_reg1_src(self):
        return self.__reg1 == SOURCE

    def is_reg2_src(self):
        return self.__reg2 == SOURCE

    def is_reg1_aux(self):
        return self.__reg1 == AUXILIARY

    def is_reg2_aux(self):
        return self.__reg2 == AUXILIARY

    def is_reg1_address(self):
        return self.__reg1 == DESTINATION_ADDRESS

    def is_reg2_address(self):
        return self.__reg2 == DESTINATION_ADDRESS

    def get_mnemonic(self):
        return self.__mnemonic

    def __str__(self):
        string = ''
        if len(self.__reg1) != 0 and len(self.__reg2) != 0:
            string = str(self.__mnemonic) + ' ' + str(self.__reg1) + ', ' + str(self.__reg2)
        elif len(self.__reg1) != 0 and len(self.__reg2) == 0:
            string = str(self.__mnemonic) + ' ' + str(self.__reg1)
        elif len(self.__reg1) == 0:
            string = str(self.__mnemonic)
        return string
