import datetime

from easyrop.knowndlls import *
from easyrop.binaries.binary import *
from easyrop.args import Args
from easyrop.core import Core


REGISTERS = ["rax", "rbx", "rcx", "rdx",
             "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "eip", "esp",
             "ax", "bx", "cx", "dx",
             "ah", "bh", "ch", "dh",
             "al", "bl", "cl", "dl"]


class RopGenerator:
    def __init__(self, binary, rop_file, ropchain, dlls):
        self.__operations = {}
        self.__binary = binary
        self.__rop_file = rop_file
        self.__enable_ropchain = ropchain
        self.__enable_dlls = dlls

    def generate(self):
        start = datetime.datetime.now()
        ops = self.read_file()
        if ops:
            if self.__enable_dlls:
                self.search_ops_dlls(ops)
            else:
                self.search_ops(ops, self.__binary)
            end = datetime.datetime.now() - start
            # print time
            print('\nTime elapsed: %s' % str(end))

    def search_ops_dlls(self, ops):
        knowndlls = KnownDlls()
        dlls = knowndlls.get_dlls()
        dlls_path = knowndlls.get_absolute_paths(dlls)
        for dll in dlls_path:
            print("=" * 80)
            if self.search_ops(ops, dll):
                break
            print("We haven't all of them yet, let's keep searching...\n")

    def search_ops(self, ops, binary):
        print("Searching gadgets on %s" % binary)
        gadgets = self.all_gadgets(binary)
        print("Trying to generate your ROP chains...\n")
        gadgets = self.get_gadgets_of_operations(ops, binary, gadgets)
        self.__operations[binary] = gadgets
        combinations = self.regs_combinations(ops, gadgets)
        if not self.has_all_combinations(combinations):
            if self.can_combine_dlls():
                gads = []
                for key in self.__operations.keys():
                    gads += self.__operations[key]
                combinations = self.regs_combinations(ops, gads)
                if not self.has_all_combinations(combinations):
                    return False
                else:
                    self.print_combinations(ops, combinations, gads)
                    return True
            return False
        self.print_combinations(ops, combinations, gadgets)
        return True

    def can_combine_dlls(self):
        return len(self.__operations) > 1

    def has_all_combinations(self, combinations):
        res = True
        for comb in combinations:
            res &= self.is_empty_combination(comb)
        return res

    def is_empty_combination(self, combination):
        return len(combination["values"]) != 0

    def get_gadgets_of_operations(self, ops, binary, gads):
        gadgets = []
        for op in ops:
            op2, dst, src = self.parse_op(op)
            argv = ('--binary %s --op %s' % (binary, op2))
            if dst in REGISTERS:
                argv += " --reg-dst %s" % dst
            if src in REGISTERS:
                argv += " --reg-src %s" % src
            args, core = self.make_core(argv)
            gadgets += [{"op": op, "gadget": core.search_operation(gads, args.op, args.reg_src, args.reg_dst)}]
        return gadgets

    def regs_combinations(self, ops, gadgets):
        combinations = []

        for op in ops:
            for gadget in gadgets:
                if gadget["op"] == op:
                    regs = set()
                    for gad in gadget["gadget"]:
                        if gad["dst"] and gad["src"]:
                            regs.add((gad["dst"], gad["src"]))
                        elif gad["dst"]:
                            regs.add((gad["dst"]))
                        elif gad["src"]:
                            regs.add((gad["src"]))

                    combinations.append({op: regs})
        return self.common_regs(ops, combinations, gadgets)

    def common_regs(self, ops, combinations, gadgets):
        regs = self.get_regs_single_operations(combinations, ops)
        regs = self.clean_nonexists_operations(gadgets, ops, regs)
        regs = self.clean_nonexists_operations(gadgets, ops, regs)

        res = []

        keys = regs.keys()
        for k in keys:
            res.append({"reg": k, "values": regs[k]})

        return res

    def get_regs_single_operations(self, combinations, ops):
        res = {}
        for op in ops:
            regs = []
            operation, dst, src = self.parse_op(op)
            if (dst and not src) or (src and not dst):
                for comb in combinations:
                    try:
                        if len(regs) == 0:
                            regs += list(comb[op])
                        else:
                            regs = list(comb[op].intersection(regs))
                        if dst:
                            res.update({dst: regs})
                        elif src:
                            res.update({src: regs})
                    except KeyError:
                        pass
        return res

    def clean_nonexists_operations(self, gadgets, ops, regs):
        for op in ops:
            dsts = set()
            srcs = set()
            operation, dst, src = self.parse_op(op)
            if dst and src:
                for gadget in gadgets:
                    if gadget["op"] == op:
                        for gad in gadget["gadget"]:
                            if dst not in REGISTERS and src not in REGISTERS:
                                try:
                                    if gad["dst"] in regs[dst] and gad["src"] in regs[src]:
                                        dsts.add(gad["dst"])
                                        srcs.add(gad["src"])
                                except KeyError:
                                    srcs.add(gad["src"])
                                    dsts.add(gad["dst"])
                            elif dst in REGISTERS and src not in REGISTERS:
                                if gad["src"] in regs[src]:
                                    srcs.add(gad["src"])
                            elif src in REGISTERS and dst not in REGISTERS:
                                if gad["dst"] in regs[dst]:
                                    dsts.add(gad["dst"])
                try:
                    if dst not in REGISTERS:
                        regs[dst] = list(dsts.intersection(regs[dst]))
                except KeyError:
                    regs.update({dst: dsts})
                try:
                    if src not in REGISTERS:
                        regs[src] = list(srcs.intersection(regs[src]))
                except KeyError:
                    regs.update({src: srcs})
        return regs

    def make_core(self, argv):
        argv_split = argv.split()
        args = Args(argv_split).get_args()
        core = Core(args)
        return args, core

    def all_gadgets(self, binary):
        argv = ('--binary %s %s' % (binary, self.args_string()))
        argv = argv.split()
        args = Args(argv).get_args()
        core = Core(args)
        gadgets = core.analyze(True)
        return core.pass_clean(gadgets)

    def read_file(self):
        try:
            return [line.rstrip('\n') for line in open(self.__rop_file)]
        except:
            print("[Error] Bad file %s" % self.__rop_file)
            sys.exit(-1)

    def parse_op(self, op):
        dst = None
        src = None
        partition = op.rpartition('(')
        op = partition[0]
        operands = partition[2].replace(')', '')
        if len(operands) != 0:
            dst, src = self.parse_operands(operands)
        return op, dst, src

    def parse_operands(self, operands):
        dst = None
        src = None
        operands = operands.split(',')
        operands = [operand.replace(' ', '') for operand in operands]
        if len(operands) == 1:
            dst = operands[0]
        elif len(operands) == 2:
            dst = operands[0]
            src = operands[1]
        return dst, src

    def args_string(self):
        args_string = ""
        args = Args(sys.argv[1:]).get_args()
        if args.depth != 5:
            args_string += " --depth %s" % args.depth
        if args.all:
            args_string += " --all"
        if args.nojop:
            args_string += " --nojop"
        if args.noretf:
            args_string += " --noretf"
        return args_string

    def print_combinations(self, ops, combinations, gadgets):
        for op in ops:
            print(op)
            for gadget in gadgets:
                if op == gadget["op"]:
                    for gad in gadget["gadget"]:
                        operation, dst, src = self.parse_op(op)
                        if dst and src:
                            if dst in REGISTERS and src in REGISTERS:
                                self.print_gadget(gad)
                            else:
                                values_dst = self.get_values_of_reg(dst, combinations)
                                values_src = self.get_values_of_reg(src, combinations)
                                if gad["dst"] in values_dst and gad["src"] in values_src:
                                    self.print_gadget(gad)
                                elif (dst in REGISTERS and gad["src"] in values_src) or \
                                        (src in REGISTERS and gad["dst"] in values_dst):
                                    self.print_gadget(gad)
                        elif dst:
                            values_dst = self.get_values_of_reg(dst, combinations)
                            if gad["dst"] in values_dst:
                                self.print_gadget(gad)
                        elif src:
                            values_src = self.get_values_of_reg(src, combinations)
                            if gad["src"] in values_src:
                                self.print_gadget(gad)
                        else:
                            self.print_gadget(gad)

    def print_gadget(self, gad):
        print("\t0x%x: %s %s" % (gad["gadget"]["vaddr"], gad["gadget"]["gadget"], gad["values"]))

    def get_values_of_reg(self, reg, combinations):
        res = []
        for com in combinations:
            if com["reg"] == reg:
                res += com["values"]
        return res
