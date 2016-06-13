class Operation:
    def __init__(self, name):
        self.__name = name
        self.__sets = []

    def addSet(self, set):
        self.__sets.append(set)

    def getSets(self):
        return self.__sets

    def __str__(self):
        string = ''
        for set in self.__sets:
            string += str(set) + '\n'
        return string
