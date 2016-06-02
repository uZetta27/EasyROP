import xml.etree.ElementTree


class XmlParser:
    def __init__(self, path):
        self.__file = xml.etree.ElementTree.parse(path).getroot()
        self.__operations = []

    def parse(self):
        for operation in self.__file.findall('operation'):
            if operation.get('name') == 'move':
                for gadget in operation.iter('gadget'):
                    size = gadget.get('size')
                    if size is not None:
                        print('(%s bytes)' % gadget.get('size'))
                    for ins in gadget.iter('ins'):
                        print(ins.get('mnemonic'), end=" ")
                        dest = ins.find('dest')
                        src = ins.find('src')
                        if src is not None:
                            print(src.text, end=" ")
                        if dest is not None:
                            print(dest.text)
                    print()
