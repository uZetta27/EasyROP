from easyrop.util.xmlParser import XmlParser

class Parser:
    def __init__(self, path):
        self.__path = path
        self.__file = None

        try:
            self.__file = XmlParser(path)
        except:
            print("[Error] Can't open the gadget source (%s)" % path)
            return None

    def parse(self):
        return self.__file.parse()
