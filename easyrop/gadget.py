class Gadget:
    def __init__(self, size):
        self.__instructions = []
        if size is None:
            self.__size = '?'
        else:
            self.__size = size

    def addIntruction(self, instruction):
        self.__instructions.append(instruction)

    def getInstructions(self):
        return self.__instructions

    def getSize(self):
        return self.__size

    def __str__(self):
        string = '(' + self.__size + ' bytes)\n'
        for instruction in self.__instructions:
            string += str(instruction)
        return string + '\n'
