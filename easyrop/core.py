import re
import os

from capstone import *

class Core:
    def __init__(self, binary, options):
        self.binary = binary
        self.options = options

    def analyze(self):
        gadget_terminations = self.add_rop_gadgets()
        if not self.options.nojop:
            gadget_terminations += self.add_jop_gadgets()

        gadgets = self.search_gadgets(gadget_terminations)
        gadgets = self.pass_clean(gadgets)

        if not self.options.all:
            gadgets = self.delete_duplicate_gadgets(gadgets)

        return self.alpha_sortgadgets(gadgets)

    def add_rop_gadgets(self):
        gadgets = [
            b"\xc3",               # ret
            b"\xc2[\x00-\xff]{2}"  # ret <imm>
        ]
        if not self.options.noretf:
            gadgets += [
                b"\xcb",                # retf
                b"\xca[\x00-\xff]{2}"   # retf <imm>
            ]

        return gadgets

    def add_jop_gadgets(self):
        gadgets = [
            b"\xff[\x20\x21\x22\x23\x26\x27]{1}",      # jmp  [reg]
            b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}",  # jmp  [reg]
            b"\xff[\x10\x11\x12\x13\x16\x17]{1}",      # jmp  [reg]
            b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}"   # call [reg]
        ]

        return gadgets

    def search_gadgets(self, gadget_terminations):
        ret = []

        section = self.binary.get_exec_sections()
        vaddr = self.binary.get_entry_point()
        arch = self.binary.get_arch()
        mode = self.binary.get_arch_mode()

        md = Cs(arch, mode)

        for termination in gadget_terminations:
            all_ref_ret = [m.end() for m in re.finditer(termination, section)]
            for ref in all_ref_ret:
                for depth in range(1, self.options.depth + 1):
                    bytes_ = section[ref - depth:ref]
                    decodes = md.disasm(bytes_, vaddr + ref - depth)
                    gadget = ""
                    for decode in decodes:
                        gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                    if len(gadget) > 0:
                        gadget = gadget[:-3]
                        ret += [{"file": os.path.basename(self.binary.get_file_name()), "vaddr": vaddr + ref - depth, "gadget": gadget, "bytes": bytes_, "values": ""}]
        return ret

    def pass_clean(self, gadgets):
        new = []
        br = ["ret"]
        if not self.options.noretf:
            br += ["retf"]
        if not self.options.nojop:
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
