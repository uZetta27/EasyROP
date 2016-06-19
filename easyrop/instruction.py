class Instruction:
    def __init__(self, mnemonic, src=None, dst=None):
        self.__mnemonic = mnemonic
        if src is not None:
            self.__src = src.text
        else:
            self.__src = ''
        if dst is not None:
            self.__dst = dst.text
        else:
            self.__dst = ''

    def getMnemonic(self):
        return self.__mnemonic

    def getSrc(self):
        return self.__src

    def getDest(self):
        return self.__dst

    def __str__(self):
        if not self.__dst and not self.__src:
            return str(self.__mnemonic)
        elif not self.__dst and self.__src:
            return str(self.__mnemonic) + ' ' + str(self.__src)
        elif self.__dst and not self.__src:
            return str(self.__mnemonic) + ' ' + str(self.__dst)
        else:
            return str(self.__mnemonic) + ' ' + str(self.__dst) + ', ' + str(self.__src)
