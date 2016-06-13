class Set:
    def __init__(self):
        self.__instructions = []

    def addIntruction(self, instruction):
        self.__instructions.append(instruction)

    def getInstructions(self):
        return self.__instructions

    def __str__(self):
        string = ''
        for instruction in self.__instructions:
            string += str(instruction) + " ; "
        string = string.replace('  ', ' ')
        return string[:-3]
