class Set:
    def __init__(self):
        self.__instructions = []

    def set_dst(self, dst):
        if dst:
            for ins in self.__instructions:
                ins.set_dst(dst)
                ins.set_dst_address(dst)

    def set_src(self, src):
        if src:
            for ins in self.__instructions:
                ins.set_src(src)
                ins.set_src_address(src)

    def set_aux(self, aux):
        if aux:
            for ins in self.__instructions:
                ins.set_aux(aux)

    def set_dst_address(self, address):
        if address:
            for ins in self.__instructions:
                ins.set_dst_address(address)

    def set_src_address(self, address):
        if address:
            for ins in self.__instructions:
                ins.set_src_address(address)

    def need_dst(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].need_dst()
            i += 1
        return needed

    def need_src(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].need_src()
            i += 1
        return needed

    def need_aux(self):
        needed = False
        i = 0
        while (i < len(self.__instructions)) and not needed:
            needed = self.__instructions[i].need_aux()
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
