class Instruction:
    def __init__(self, mnemonic, reg1=None, reg2=None):
        self.__mnemonic = mnemonic
        if reg1 is not None:
            self.__reg1 = reg1.text
        else:
            self.__reg1 = ''
        if reg2 is not None:
            self.__reg2 = reg2.text
        else:
            self.__reg2 = ''

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

    def getMnemonic(self):
        return self.__mnemonic

    def getSrc(self):
        return self.__reg1

    def getDest(self):
        return self.__reg2

    def __str__(self):
        if not self.__reg2 and not self.__reg1:
            return str(self.__mnemonic)
        elif not self.__reg1 and self.__reg2:
            return str(self.__mnemonic) + ' ' + str(self.__reg2)
        elif self.__reg1 and not self.__reg2:
            return str(self.__mnemonic) + ' ' + str(self.__reg1)
        else:
            return str(self.__mnemonic) + ' ' + str(self.__reg1) + ', ' + str(self.__reg2)
