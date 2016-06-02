class Gadget:
    def __init__(self):
        self.__instructions = []

    def addIntruction(self, instruction):
        self.__instructions += instruction

    def getInstructions(self):
        return self.__instructions
