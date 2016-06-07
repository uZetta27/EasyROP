from pefile import *
from capstone import *

class Pe:
    def __init__(self, fileName):
        self.__fileName = fileName
        self.__pe = None
        self.__archMode = None
        self.__arch = None

        try:
            self.__pe = PE(fileName)
        except:
            print("[Error] Can't open the binary or binary not found")
            return None

        self.__parseArch()

    def __parseArch(self):
        if hex(self.__pe.FILE_HEADER.Machine) == '0x14c':
            self.__archMode = CS_MODE_32
            self.__arch = CS_ARCH_X86
        elif hex(self.__pe.FILE_HEADER.Machine) == '0x8664':
            self.__archMode = CS_MODE_64
            self.__arch = CS_ARCH_X86

    def getFileName(self):
        return self.__fileName

    def getBinary(self):
        return self.__pe

    def getEntryPoint(self):
        return self.__pe.OPTIONAL_HEADER.ImageBase

    def getExecSections(self):
        return self.__pe.sections[0].get_data()

    def getArch(self):
        return self.__arch

    def getArchMode(self):
        return self.__archMode
