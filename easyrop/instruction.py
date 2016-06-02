class Instruction:
    def __init__(self, mnemonic, src=None, dest=None):
        self.__mnemonic = mnemonic
        self.__src = src
        self.__dest = dest

    def getMnemonic(self):
        return self.__mnemonic

    def getSrc(self):
        return self.__src

    def getDest(self):
        return self.__dest
