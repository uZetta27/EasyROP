from easyrop.binaries.pe import Pe


class Binary:
    def __init__(self, options):
        self.__fileName = options.binary
        self.__binary = None

        try:
            self.__binary = Pe(self.__fileName)
        except:
            print("[Error] Can't open the binary or binary not found")
            return None

    def getFileName(self):
        return self.__fileName

    def getBinary(self):
        return self.__binary

    def getEntryPoint(self):
        return self.__binary.getEntryPoint()

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getArch(self):
        return self.__binary.getArch()

    def getArchMode(self):
        return self.__binary.getArchMode()
