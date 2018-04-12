import copy

from capstone import *
from capstone.x86 import *

from easyrop.parsers.parser import Parser

class OpSearcher:
    def __init__(self, binary, op, dst='', src=''):
        self.md = Cs(binary.get_arch(), binary.get_arch_mode())
        self.md.detail = True

        self.op = Parser().get_operation(op)
        self.op.set_dst(dst)
        self.op.set_src(src)

    def filter_gadgets(self, gadgets):
        ret = []
        for set_ in self.op.get_sets():
            for gadget in gadgets:
                is_equal, values, dst, src = self.is_same_sequence(set_, gadget)
                if is_equal:
                    gadget["values"] = values
                    gadget["op"] = {"op": self.op.get_name(), "dst": dst, "src": src}
                    ret += [gadget]
        return ret

    def is_same_sequence(self, set_, gadget):
        dst = ""
        src = ""
        aux = ""

        for ins, decode in zip(set_.get_instructions(), self.md.disasm(gadget["bytes"], gadget["vaddr"])):
            if ins.get_mnemonic() != decode.mnemonic:
                return False, [], "", ""
            if not dst:
                if ins.is_reg1_dst():
                    dst = self.get_register(decode, 0)
                    if not dst and ins.is_reg1_address():
                        dst = self.get_register_base(decode, 0)
                elif ins.is_reg2_dst():
                    dst = self.get_register(decode, 1)
                    if not dst and ins.is_reg2_address():
                        dst = self.get_register_base(decode, 1)
            if not src:
                if ins.is_reg1_src():
                    src = self.get_register(decode, 0)
                    if not src and ins.is_reg1_address():
                        src = self.get_register_base(decode, 0)
                elif ins.is_reg2_src():
                    src = self.get_register(decode, 1)
                    if not src and ins.is_reg2_address():
                        src = self.get_register_base(decode, 1)
            if not aux:
                if ins.is_reg1_aux():
                    aux = self.get_register(decode, 0)
                    if not aux and ins.is_reg1_address():
                        aux = self.get_register_base(decode, 0)
                elif ins.is_reg2_aux():
                    aux = self.get_register(decode, 1)
                    if not aux and ins.is_reg2_address():
                        aux = self.get_register_base(decode, 1)

        saux = copy.deepcopy(set_)
        saux.set_dst(dst)
        saux.set_src(src)
        saux.set_aux(aux)

        is_equal, values = self.has_same_registers(saux, gadget)

        return is_equal, values, dst, src

    def has_same_registers(self, set_, gadget):
        values = []
        for ins, decode in zip(set_.get_instructions(), self.md.disasm(gadget["bytes"], gadget["vaddr"])):
            if ins.is_reg1_address():
               if ins.get_reg1() != self.get_register_base(decode, 0):
                    return False, values
            elif ins.get_reg1() != self.get_register(decode, 0):
                return False, values
            if ins.is_reg2_address():
               if ins.get_reg2() != self.get_register_base(decode, 1):
                    return False, values
            elif ins.get_reg2() != self.get_register(decode, 1):
                return False, values
            if ins.need_value1():
                values += ["%s = %s" % (ins.get_reg1(), ins.get_value1())]
            if ins.need_value2():
                values += ["%s = %s" % (ins.get_reg2(), ins.get_value2())]
        return True, values

    def get_register(self, decode, position):
        reg = ""
        if position < len(decode.operands):
            i = decode.operands[position]
            if i.type == X86_OP_REG:
                reg = decode.reg_name(i.reg)
        return reg

    def get_register_base(self, decode, position):
        reg = ""
        if position < len(decode.operands):
            i = decode.operands[position]
            if i.type == X86_OP_MEM:
                if i.mem.base != 0:
                    reg = decode.reg_name(i.mem.base)
        return reg
