class Instruction:
    def __init__(self, mnemonic, src=None, dest=None):
        self.__mnemonic = mnemonic
        if src is not None:
            self.__src = src.text
        else:
            self.__src = ''
        if dest is not None:
            self.__dest = dest.text
        else:
            self.__dest = ''

    def getMnemonic(self):
        return self.__mnemonic

    def getSrc(self):
        return self.__src

    def getDest(self):
        return self.__dest

    def __str__(self):
        return (str(self.__mnemonic) + ' ' + str(self.__src) + ' ' + str(self.__dest)).replace('  ', ' ')
