class Instruction:
    def __init__(self, mnemonic, reg1, reg2):
        self.__mnemonic = mnemonic
        self.__reg1 = reg1
        self.__reg2 = reg2

    def setDst(self, dst):
        if self.__reg1 == 'dst':
            self.__reg1 = dst
        if self.__reg2 == 'dst':
            self.__reg2 = dst

    def setSrc(self, src):
        if self.__reg1 == 'src':
            self.__reg1 = src
        if self.__reg2 == 'src':
            self.__reg2 = src

    def getReg1(self):
        return self.__reg1

    def getReg2(self):
        return self.__reg2

    def getMnemonic(self):
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
