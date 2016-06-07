class Operation:
    def __init__(self, name):
        self.__name = name
        self.__gadgets = []

    def addGadget(self, gadget):
        self.__gadgets.append(gadget)

    def getGadgets(self):
        return self.__gadgets

    def __str__(self):
        string = ''
        for gadget in self.__gadgets:
            string += str(gadget)
        return string
