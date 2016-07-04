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

    def addIntruction(self, instruction):
        self.__instructions.append(instruction)

    def getInstructions(self):
        return self.__instructions

    def __str__(self):
        string = ''
        for instruction in self.__instructions:
            string += str(instruction) + " ; "
        string = string.replace('  ', ' ').replace(', ;', ' ;')

        return string
