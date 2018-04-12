import os
import __main__
import re

from easyrop.binaries.binary import Binary
from easyrop.core import Core
from easyrop.op_searcher import OpSearcher

class RopGenerator:
    def __init__(self, options, debug=False):
        self.options = options
        self.debug = debug

    def analyze(self):
        ret = []
        gadgets = []

        ops = self.parse_rop_file(self.options.ropchain)
        for binary in self.options.binary:
            common = {}
            if self.debug:
                print("[+] Analyzing %s" % os.path.basename(binary))
            bin_ = Binary(binary)
            gadgets += Core(bin_, self.options).analyze()
            for op in ops:
                op_gadgets = OpSearcher(bin_, op["op"], op["dst"], op["src"]).filter_gadgets(gadgets)
                common = self.get_commong_registers(common, op_gadgets, op)
                ret += op_gadgets
            if self.has_all_combinations(common):
                return self.order_ropchains(ret, ops, common)
        return []

    def order_ropchains(self, gadgets, ops, common):
        ropchains = []

        for op in ops:
            filtered_gadgets = []
            for gadget in gadgets:
                if gadget["op"]["op"] == op["op"]:
                    if gadget["op"]["dst"] in common[op["dst"]] and gadget["op"]["src"] in common[op["src"]]:
                        filtered_gadgets += [gadget]
            ropchains += [{"op": op, "gadgets": filtered_gadgets}]

        return ropchains

    def has_all_combinations(self, combinations):
        for key in combinations.keys():
            if not len(combinations[key]):
                return False
        return True

    def get_commong_registers(self, common, gadgets, op):
        dsts = []
        srcs = []
        for gadget in gadgets:
            dsts += [gadget["op"]["dst"]]
            srcs += [gadget["op"]["src"]]

        ret = {op["dst"]: set(dsts), op["src"]: set(srcs)}
        #ret.pop('', None)

        if len(common):
            return self.filter_registers(common, ret)
        else:
            return ret

    def filter_registers(self, common, regs):
        for key in common.keys():
            if key in regs:
                common[key] = regs[key].intersection(list(common[key]))
        for key in regs.keys():
            if key not in common:
                common[key] = regs[key]

        return common

    def parse_rop_file(self, file):
        ret = []
        try:
            for op in [line.rstrip('\n') for line in open(file)]:
                ret += [self.parse_op(op)]
        except (FileNotFoundError, UnicodeDecodeError, IsADirectoryError):
            print("%s: '%s': Not a plain text file" % (os.path.basename(__main__.__file__), os.path.realpath(file)))
            raise FileNotFoundError

        return ret

    def parse_op(self, op):
        try:
            match = re.search(r'^([a-zA-Z0-9_\-]+)\(([a-zA-Z0-9,_\- ]*)\)$', op)
            op_parsed = match.group(1)
            reg1, reg2 = self.parse_operands(match.group(2))
        except AttributeError:
            print("%s: '%s': Compile error, must be like 'operation(reg1, reg2)', 'operation(reg1)' or 'operation()'" % (os.path.basename(__main__.__file__), op))
            raise

        return {"original": op, "op": op_parsed, "dst": reg1, "src": reg2}

    def parse_operands(self, operands):
        reg1 = ""
        reg2 = ""
        splited = operands.replace(' ', '').split(',')
        try:
            reg1 = splited[0]
            reg2 = splited[1]
        except IndexError:
            pass

        return reg1, reg2
