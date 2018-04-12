from easyrop.registers import REGISTERS_X86

class Operation:
    def __init__(self, name):
        self._name = name
        self._sets = []

    def add_set(self, set_):
        self._sets += [set_]

    def get_sets(self):
        return self._sets

    def set_dst(self, dst):
        if dst and dst in REGISTERS_X86:
            for set_ in self._sets:
                set_.set_dst(dst)

    def set_src(self, src):
        if src and src in REGISTERS_X86:
            for set_ in self._sets:
                set_.set_src(src)

    def get_name(self):
        return self._name

    def __str__(self):
        string = ""
        for set_ in self._sets:
            string += str(set_) + "\n"
        return string[:-1].replace('  ', ' ')
