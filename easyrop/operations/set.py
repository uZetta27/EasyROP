class Set:
    def __init__(self):
        self._instructions = []

    def add_instruction(self, instruction):
        self._instructions += [instruction]

    def get_instructions(self):
        return self._instructions

    def set_dst(self, dst):
        if dst:
            for ins in self._instructions:
                ins.set_dst(dst)

    def set_src(self, src):
        if src:
            for ins in self._instructions:
                ins.set_src(src)

    def set_aux(self, aux):
        if aux:
            for ins in self._instructions:
                ins.set_aux(aux)

    def __str__(self):
        string = ""
        for ins in self._instructions:
            string += str(ins) + " ; "
        return string[:-3].replace('  ', ' ')

    def __len__(self):
        return len(self._instructions)
