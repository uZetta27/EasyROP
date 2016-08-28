import datetime
import re
from capstone import *
from capstone.x86 import *
from easyrop.binaries.binary import Binary
from easyrop.instruction import *
from easyrop.parsers.parser import Parser


INSTRUCTION_OP = 0
INSTRUCTION_SIZE = 1


class Core:
    def __init__(self, options):
        self.__options = options
        self.__gadgets = []

    def analyze(self, silent=False):
        start = datetime.datetime.now()
        # search for gadgets
        self.__gadgets += self.add_rop_gadgets()
        if not self.__options.nojop:
            self.__gadgets += self.add_jop_gadgets()
        # apply some options
        if not self.__options.all:
            self.__gadgets = self.delete_duplicate_gadgets(self.__gadgets)
        self.__gadgets = self.pass_clean(self.__gadgets)
        self.__gadgets = self.alpha_sortgadgets(self.__gadgets)
        # print operation
        if self.__options.op:
            # print ropchain
            if self.__options.ropchain:
                ropchains = self.search_ropchains(self.__gadgets, self.__options.op, self.__options.reg_src, self.__options.reg_dst)
                if not silent:
                    self.print_ropchains(ropchains)
            else:
                gadgets = self.search_operation(self.__gadgets, self.__options.op, self.__options.reg_src, self.__options.reg_dst)
                if not silent:
                    self.print_operation(gadgets)
        else:
            if not silent:
                self.print_gadgets(self.__gadgets)
        end = datetime.datetime.now() - start
        # print time
        if not silent:
            print('\nTime elapsed: %s' % str(end))
        else:
            return self.__gadgets

    def add_rop_gadgets(self):
        gadgets = [
            [b"\xc3", 1],               # ret
            [b"\xc2[\x00-\xff]{2}", 3]  # ret <imm>
        ]
        if not self.__options.noretf:
            gadgets += [
                [b"\xcb", 1],                # retf
                [b"\xca[\x00-\xff]{2}", 3]   # retf <imm>
            ]

        return self.search_gadgets(gadgets)

    def add_jop_gadgets(self):
        gadgets = [
            [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2],      # jmp  [reg]
            [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2],  # jmp  [reg]
            [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2],      # jmp  [reg]
            [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2]   # call [reg]
        ]

        return self.search_gadgets(gadgets)

    def search_gadgets(self, gadgets):
        binary = Binary(self.__options.binary)
        section = binary.get_exec_sections()
        vaddr = binary.get_entry_point()
        arch = binary.get_arch()
        mode = binary.get_arch_mode()

        ret = []
        md = Cs(arch, mode)
        for gad in gadgets:
            all_ref_ret = [m.start() for m in re.finditer(gad[INSTRUCTION_OP], section)]
            for ref in all_ref_ret:
                for depth in range(self.__options.depth):
                        decodes = md.disasm(section[ref - depth:ref + gad[INSTRUCTION_SIZE]], vaddr + ref - depth)
                        gadget = ""
                        for decode in decodes:
                            gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                        if len(gadget) > 0:
                            gadget = gadget[:-3]
                            ret += [{"vaddr": vaddr + ref - depth, "gadget": gadget, "bytes": section[ref - depth:ref + gad[INSTRUCTION_SIZE]]}]
        return ret

    def search_operation(self, gadgets, op, src, dst):
        binary = Binary(self.__options.binary)
        ret = []
        parser = Parser(op)
        arch = binary.get_arch()
        mode = binary.get_arch_mode()
        md = Cs(arch, mode)
        md.detail = True
        operation = parser.get_operation()
        if ((operation.need_src() and src) or (operation.need_dst() and dst)) and\
                not ((operation.need_src() and not src) or (operation.need_dst() and not dst)):
            operation.set_dst(dst)
            operation.set_src(src)
            sets = operation.get_sets()
            for s in sets:
                if s.need_aux():
                    for gadget in gadgets:
                        _aux = None
                        decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                        for decode, ins in zip(decodes, s.get_instructions()):
                            if decode.mnemonic == ins.get_mnemonic():
                                if len(decode.operands) > 0:
                                    _aux = self.get_set_aux(_aux, decode, ins)
                            else:
                                break
                        else:
                            saux = copy.deepcopy(s)
                            saux.set_aux(_aux)
                            decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                            same, values = self.same_gadget_set(decodes, saux)
                            if same:
                                ret += [{"gadget": gadget, "values": values}]
                else:
                    for gadget in gadgets:
                        decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                        same, values = self.same_gadget_set(decodes, s)
                        if same:
                            ret += [{"gadget": gadget, "values": values}]
        else:
            for gadget in gadgets:
                operation = parser.get_operation()
                sets = operation.get_sets()
                for s in sets:
                    _dst = dst
                    _src = src
                    _aux = None
                    decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                    for decode, ins in zip(decodes, s.get_instructions()):
                        if decode.mnemonic == ins.get_mnemonic():
                            if len(decode.operands) > 0:
                                _aux, _dst, _src = self.get_operands_set(_aux, _dst, _src, decode, ins)
                        else:
                            break
                    else:
                        s.set_dst(_dst)
                        s.set_src(_src)
                        s.set_aux(_aux)
                        decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                        same, values = self.same_gadget_set(decodes, s)
                        if same:
                            ret += [{"gadget": gadget, "values": values}]
        return ret

    def get_operands_set(self, _aux, _dst, _src, decode, ins):
        _aux = self.get_set_aux(_aux, decode, ins)
        _dst = self.get_set_dst(_dst, decode, ins)
        _src = self.get_set_src(_src, decode, ins)

        return _aux, _dst, _src

    def get_set_aux(self, _aux, decode, ins):
        if not _aux:
            if ins.is_aux(REG1):
                _aux = self.get_register(decode, REG1)
            elif ins.is_aux(REG2):
                _aux = self.get_register(decode, REG2)
        return _aux

    def get_set_dst(self, _dst, decode, ins):
        if not _dst:
            if ins.is_dst_address(REG1):
                _dst = self.get_reg_base(decode, REG1)
            elif ins.is_dst(REG1):
                _dst = self.get_register(decode, REG1)
            elif ins.is_dst_address(REG2):
                _dst = self.get_reg_base(decode, REG2)
            elif ins.is_dst(REG2):
                _dst = self.get_register(decode, REG2)
        return _dst

    def get_set_src(self, _src, decode, ins):
        if not _src:
            if ins.is_src_address(REG1):
                _src = self.get_reg_base(decode, REG1)
            elif ins.is_src(REG1):
                _src = self.get_register(decode, REG1)
            elif ins.is_src_address(REG2):
                _src = self.get_reg_base(decode, REG2)
            elif ins.is_src(REG2):
                _src = self.get_register(decode, REG2)
        return _src

    def same_gadget_set(self, decodes, set_):
        values = ''
        for decode, ins in zip(decodes, set_.get_instructions()):
            same, v = self.same_gadget_ins(decode, ins)
            if not same:
                break
            values += v
        else:
            return True, values

        return False, values

    def same_gadget_ins(self, decode, ins):
        same = True
        values = ''
        if decode.mnemonic == ins.get_mnemonic():
            if len(decode.operands) > 0:
                if ins.there_is_reg(REG1):
                    if ins.need_value(REG1):
                        values += ins.get_value(REG1)
                    if ins.is_address(REG1):
                        if ins.get_register(REG1) != self.get_reg_base(decode, REG1):
                            same = False
                    else:
                        if ins.get_register(REG1) != self.get_register(decode, REG1):
                            same = False
                if same and ins.there_is_reg(REG2):
                    if ins.need_value(REG2):
                        values += ins.get_value(REG2)
                    if ins.is_address(REG2):
                        if ins.get_register(REG2) != self.get_reg_base(decode, REG2):
                            same = False
                    else:
                        if ins.get_register(REG2) != self.get_register(decode, REG2):
                            same = False
        else:
            same = False
        return same, values

    def search_ropchains(self, gadgets, op, src, dst):
        binary = Binary(self.__options.binary)
        gadgets = self.lenght_sortgadgets(gadgets)
        arch = binary.get_arch()
        mode = binary.get_arch_mode()
        md = Cs(arch, mode)
        md.detail = True
        parser = Parser(op)
        ret = []
        operation = parser.get_operation()
        if ((operation.need_src() and src) or (operation.need_dst() and dst)) and \
                not ((operation.need_src() and not src) or (operation.need_dst() and not dst)):
            operation.set_dst(dst)
            operation.set_src(src)
            sets = operation.get_sets()
            for s in sets:
                if len(s) > 1:
                    chain = []
                    if s.need_aux():
                        i = 0
                        j = 0
                        _aux = None
                        searched_aux = []
                        while (j < len(gadgets)) and (i < len(s)):
                            decodes = md.disasm(gadgets[j]["bytes"], gadgets[j]["vaddr"])
                            decode = next(decodes)
                            ins = s.get_instructions()[i]
                            if decode.mnemonic == ins.get_mnemonic():
                                if len(decode.operands) > 0:
                                    temp = self.get_set_aux(_aux, decode, ins)
                                    if temp not in searched_aux:
                                        _aux = temp
                                        saux = copy.deepcopy(s)
                                        saux.set_aux(_aux)
                                        decodes = md.disasm(gadgets[j]["bytes"], gadgets[j]["vaddr"])
                                        same, values = self.same_gadget_ins(next(decodes), saux.get_instructions()[i])
                                        if same:
                                            chain += [{"gadget": gadgets[j], "values": values}]
                                            i += 1
                                            j = -1
                                else:
                                    chain += [{"gadget": gadgets[j], "values": ''}]
                                    i += 1
                                    j = -1
                            j += 1
                            if j == len(gadgets):
                                if _aux is not None:
                                    i = 0
                                    j = 0
                                    searched_aux += [_aux]
                                    _aux = None
                                    chain = []
                    else:
                        for ins in s.get_instructions():
                            for gadget in gadgets:
                                decodes = md.disasm(gadget["bytes"], gadget["vaddr"])
                                same, values = self.same_gadget_ins(next(decodes), ins)
                                if same:
                                    chain += [{"gadget": gadget, "values": values}]
                                    break
                    if len(s) == len(chain):
                        ret += [chain]
        return ret

    def get_string(self, decode):
        return ("%s %s" % (decode.mnemonic, decode.op_str)).replace("  ", " ")

    def get_register(self, decode, position):
        reg = None
        if position < len(decode.operands):
            i = decode.operands[position]
            if i.type == X86_OP_REG:
                reg = decode.reg_name(i.reg)
        return reg

    def get_reg_base(self, decode, position):
        reg = None
        if position < len(decode.operands):
            i = decode.operands[position]
            if i.type == X86_OP_MEM:
                if i.mem.base != 0:
                    reg = decode.reg_name(i.mem.base)
        return reg

    def print_gadgets(self, gadgets):
        print("Gadgets information")
        print("============================================================")
        for gad in gadgets:
            print("0x%x : %s" % (gad["vaddr"], gad["gadget"]))
        print("\nGadgets found: %d" % len(gadgets))

    def print_operation(self, gadgets):
        print("Operation \'%s\' gadgets" % self.__options.op)
        print("============================================================")
        for gad in gadgets:
            print("0x%x : %s %s" % (gad["gadget"]["vaddr"], gad["gadget"]["gadget"], gad["values"]))
        print("\nGadgets found: %d" % len(gadgets))

    def print_ropchains(self, ropchains):
        print("ROPchains information")
        print("============================================================")
        for chain in ropchains:
            for gad in chain:
                print("0x%x : %s %s" % (gad["gadget"]["vaddr"], gad["gadget"]["gadget"], gad["values"]))
            print('-----------------------------------------')
        print("\nROPchains found: %d" % len(ropchains))

    def delete_duplicate_gadgets(self, gadgets):
        gadgets_content_set = set()
        unique_gadgets = []
        for gadget in gadgets:
            gad = gadget["gadget"]
            if gad in gadgets_content_set:
                continue
            gadgets_content_set.add(gad)
            unique_gadgets += [gadget]
        return unique_gadgets

    def alpha_sortgadgets(self, current_gadgets):
        return sorted(current_gadgets, key=lambda gadget: gadget["gadget"])

    def lenght_sortgadgets(self, current_gadgets):
        return sorted(current_gadgets, key=lambda gadget: len(gadget["bytes"]))

    def pass_clean(self, gadgets):
        new = []
        br = ["ret"]
        if not self.__options.noretf:
            br += ["retf"]
        if not self.__options.nojop:
            br += ["jmp", "call"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new
