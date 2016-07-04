class Operation:
    def __init__(self, name):
        self.__name = name
        self.__sets = []

    def setDst(self, dst):
        if dst:
            for s in self.__sets:
                s.setDst(dst)

    def setSrc(self, src):
        if src:
            for s in self.__sets:
                s.setSrc(src)

    def addSet(self, s):
        self.__sets.append(s)

    def getSets(self):
        return self.__sets

    def __str__(self):
        string = ''
        for s in self.__sets:
            string += str(s) + '\n'
        return string
