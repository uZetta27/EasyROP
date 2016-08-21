class Set:
    def __init__(self):
        self.__instructions = []

    def set_dst(self, dst):
        if dst:
            for ins in self.__instructions:
                ins.set_dst(dst)

    def set_src(self, src):
        if src:
            for ins in self.__instructions:
                ins.set_src(src)

    def set_aux(self, aux):
        if aux:
            for ins in self.__instructions:
                ins.set_aux(aux)

    def set_address(self, address):
        if address:
            for ins in self.__instructions:
                ins.set_address(address)

    def need_aux(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].need_aux()
            i += 1
        return needed

    def need_address(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].need_address()
            i += 1
        return needed

    def add_instruction(self, instruction):
        self.__instructions += [instruction]

    def get_instructions(self):
        return self.__instructions

    def __str__(self):
        string = ''
        for instruction in self.__instructions:
            string += str(instruction) + " ; "
        string = string.replace('  ', ' ')

        return string

    def __len__(self):
        return len(self.__instructions)
