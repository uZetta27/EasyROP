class Operation:
    def __init__(self, name):
        self.__name = name
        self.__gadgets = []

    def getGadgets(self):
        return self.__gadgets
