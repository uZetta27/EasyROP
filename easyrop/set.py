class Set:
    def __init__(self):
        self.__instructions = []

    def setDst(self, dst):
        if dst:
            for ins in self.__instructions:
                ins.setDst(dst)

    def setSrc(self, src):
        if src:
            for ins in self.__instructions:
                ins.setSrc(src)

    def setAux(self, aux):
        if aux:
            for ins in self.__instructions:
                ins.setAux(aux)

    def setAddress(self, address):
        if address:
            for ins in self.__instructions:
                ins.setAux(address)

    def needAux(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].needAux()
            i += 1
        return needed

    def needAddress(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].needAddress()
            i += 1
        return needed

    def addIntruction(self, instruction):
        self.__instructions += [instruction]

    def getInstructions(self):
        return self.__instructions

    def __str__(self):
        string = ''
        for instruction in self.__instructions:
            string += str(instruction) + " ; "
        string = string.replace('  ', ' ')

        return string

    def __len__(self):
        return len(self.__instructions)
