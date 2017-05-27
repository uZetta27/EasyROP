import datetime

from easyrop.knowndlls import *
from easyrop.args import Args
from easyrop.core import Core


REGISTERS = ["rax", "rbx", "rcx", "rdx",
             "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "eip", "esp",
             "ax", "bx", "cx", "dx",
             "ah", "bh", "ch", "dh",
             "al", "bl", "cl", "dl"]


class RopGenerator:
    def __init__(self, binary, rop_file, ropchain, dlls):
        self.__gadgets = []
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
            print("Searhing in %s" % dll)
            if self.search_ops(ops, dll):
                break
            print("Nothing found!")

    def search_ops(self, ops, binary):
        self.all_gadgets(binary)
        regs = self.potential_regs_combination(ops, binary)
        combinations = self.ops_combinations(ops, regs, binary)
        ops_completed = self.all_combinations(combinations)
        if len(ops_completed) != len(ops):
            return False
        self.print_combinations(ops, combinations)
        return True

    def all_combinations(self, combinations):
        op_list = set()
        gadgets = combinations["gadgets"]
        for gad in gadgets:
            op_list.add(list(gad.keys())[0])
        return op_list

    def potential_regs_combination(self, ops, binary):
        regs = {}
        searched_dsts = []
        searched_srcs = []
        i = 0
        while i < len(ops):
            operation, dst, src = self.parse_op(ops[i])
            if (dst not in searched_dsts) or (src not in searched_srcs):
                j = i
                while j < len(ops):
                    op2, dst2, src2 = self.parse_op(ops[j])
                    argv = ('--binary %s --op %s' % (binary, op2))
                    if dst2 in REGISTERS:
                        argv += " --reg-dst %s" % dst2
                    if src2 in REGISTERS:
                        argv += " --reg-src %s" % src2
                    args, core = self.make_core(argv)
                    gadgets = core.search_operation(self.__gadgets, args.op, args.reg_src, args.reg_dst)
                    if (dst is not None) and (dst == dst2):
                        searched_dsts += [dst]
                        regs = self.search_dsts(args, core, gadgets, regs, op2, dst)
                    if (src is not None) and (src == src2):
                        searched_srcs += [src]
                        regs = self.search_srcs(args, core, gadgets, regs, op2, src)
                    j += 1
            i += 1
        return regs

    def search_dsts(self, args, core, gadgets, regs, op, dst):
        if len(gadgets) == 0 and self.__enable_ropchain:
            ropchains = core.search_ropchains(self.__gadgets, args.op, args.reg_src, args.reg_dst)
            if len(ropchains) != 0:
                if dst not in regs:
                    regs.update({dst: []})
                regs.update({dst: self.common_dsts(core, regs[dst], gadgets, op)})
        else:
            if dst not in REGISTERS:
                if dst not in regs:
                    regs.update({dst: []})
                regs.update({dst: self.common_dsts(core, regs[dst], gadgets, op)})
        return regs

    def search_srcs(self, args, core, gadgets, regs, op, src):
        if len(gadgets) == 0 and self.__enable_ropchain:
            ropchains = core.search_ropchains(self.__gadgets, args.op, args.reg_src, args.reg_dst)
            if len(ropchains) != 0:
                if src not in regs:
                    regs.update({src: []})
                regs.update({src: self.common_srcs(core, regs[src], gadgets, op)})
        elif len(gadgets) != 0:
            if src not in REGISTERS:
                if src not in regs:
                    regs.update({src: []})
                regs.update({src: self.common_srcs(core, regs[src], gadgets, op)})
        return regs

    def ops_combinations(self, ops, regs, binary):
        combinations = {"gadgets": [], "ropchains": []}
        for operation in ops:
            op, dst, src = self.parse_op(operation)
            if (dst is not None) and (src is not None):
                destination = self.registers(dst, regs)
                source = self.registers(src, regs)
                for d in destination:
                    for s in source:
                        argv = ('--binary %s --op %s' % (binary, op))
                        argv += " --reg-dst %s" % d
                        argv += " --reg-src %s" % s
                        combinations = self.update_combinations(argv, combinations, operation)
            elif dst is not None:
                destination = self.registers(dst, regs)
                for d in destination:
                    argv = ('--binary %s --op %s' % (binary, op))
                    argv += " --reg-dst %s" % d
                    combinations = self.update_combinations(argv, combinations, operation)
            elif src is not None:
                source = self.registers(src, regs)
                for s in source:
                    argv = ('--binary %s --op %s' % (binary, op))
                    argv += " --reg-src %s" % s
                    combinations = self.update_combinations(argv, combinations, operation)
            elif (dst is None) and (src is None):
                argv = ('--binary %s --op %s' % (binary, op))
                combinations = self.update_combinations(argv, combinations, operation)
        return combinations

    def update_combinations(self, argv, combinations, operation):
        args, core = self.make_core(argv)
        gadgets = core.search_operation(self.__gadgets, args.op, args.reg_src, args.reg_dst)
        if len(gadgets) == 0 and self.__enable_ropchain:
            ropchains = core.search_ropchains(self.__gadgets, args.op, args.reg_src, args.reg_dst)
            if len(ropchains) != 0:
                combinations["ropchains"] += [{operation: self.best_ropchain(ropchains)}]
        elif len(gadgets) != 0:
            combinations["gadgets"] += [{operation: self.best_gadget(gadgets)}]
        return combinations

    def make_core(self, argv):
        argv_split = argv.split()
        args = Args(argv_split).get_args()
        core = Core(args)
        return args, core

    def registers(self, reg, regs):
        ret = []
        if reg in REGISTERS:
            ret = [reg]
        else:
            for r in regs:
                if reg == r:
                    ret = regs[r]
        return ret

    def common_dsts(self, core, dsts, gadgets, op):
        if len(dsts) == 0:
            return core.get_all_dsts(op, gadgets)
        else:
            return list(set(dsts).intersection(core.get_all_dsts(op, gadgets)))

    def common_srcs(self, core, srcs, gadgets, op):
        if len(srcs) == 0:
            return core.get_all_srcs(op, gadgets)
        else:
            return list(set(srcs).intersection(core.get_all_srcs(op, gadgets)))

    def all_gadgets(self, binary):
        argv = ('--binary %s %s' % (binary, self.args_string()))
        argv = argv.split()
        args = Args(argv).get_args()
        core = Core(args)
        self.__gadgets = core.analyze(True)
        self.__gadgets = core.pass_clean(self.__gadgets)

    def best_gadget(self, gadgets):
        return sorted(gadgets, key=lambda gadget: len(gadget["gadget"]["bytes"]))[0]

    def best_ropchain(self, ropchains):
        return sorted(ropchains, key=lambda chain: self.lenght_chain(chain))[0]

    def lenght_chain(self, chain):
        lenght = 0
        for gad in chain:
            lenght += len(gad["gadget"]["bytes"])
        return lenght

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

    def print_ropchain(self, ropchain):
        print("\t--------------- ropchain ---------------")
        for gadget in ropchain:
            self.print_gadget(gadget)
        print("\t----------------------------------------")

    def print_gadget(self, gadget):
        print("\t0x%x : %s %s" % (gadget["gadget"]["vaddr"], gadget["gadget"]["gadget"], gadget["values"]))

    def print_combinations(self, ops, combinations):
        for operation in ops:
            print(operation)
            if combinations["gadgets"]:
                for comb in combinations["gadgets"]:
                    if operation in comb:
                        self.print_gadget(comb[operation])
            if combinations["ropchains"]:
                for comb in combinations["ropchains"]:
                    if operation in comb:
                        self.print_ropchain(comb[operation])
