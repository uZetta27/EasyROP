import datetime
import sys

from easyrop.args import Args
from easyrop.core import Core


class RopGenerator:
    def __init__(self, binary, rop_file):
        self.__gadgets = []
        self.__binary = binary
        self.__rop_file = rop_file

    def generate(self):
        start = datetime.datetime.now()
        ops = self.read_file()
        if ops:
            print("Best ropchain")
            print("============================================================")
            for operation in ops:
                op, dst, src = self.parse_op(operation)
                print(operation)
                self.search_op(dst, op, src)
        end = datetime.datetime.now() - start
        # print time
        print('\nTime elapsed: %s' % str(end))

    def search_op(self, dst, op, src):
        argv = ('--binary %s --op %s%s' % (self.__binary, op, self.get_args_string()))
        if dst:
            argv += (' --reg-dst %s' % dst)
        if src:
            argv += (' --reg-src %s' % src)
        argv = argv.split()
        args = Args(argv).get_args()
        core = Core(args)
        if len(self.__gadgets) == 0:
            self.__gadgets = core.analyze(True)
            self.__gadgets = core.pass_clean(self.__gadgets)
        gadgets = core.search_operation(self.__gadgets, args.op, args.reg_src, args.reg_dst)
        if len(gadgets) == 0:
            ropchains = core.search_ropchains(self.__gadgets, args.op, args.reg_src, args.reg_dst)
            if len(ropchains) == 0:
                print("\tNot found!")
            else:
                self.print_ropchain(self.get_best_ropchain(ropchains))
        else:
            self.print_gadget(self.get_best_gadget(gadgets))

    def print_ropchain(self, ropchain):
        for gadget in ropchain:
            self.print_gadget(gadget)

    def print_gadget(self, gadget):
        print("\t0x%x : %s %s" % (gadget["gadget"]["vaddr"], gadget["gadget"]["gadget"], gadget["values"]))

    def get_best_ropchain(self, ropchains):
        return sorted(ropchains, key=lambda chain: self.lenght_chain(chain))[0]

    def lenght_chain(self, chain):
        lenght = 0
        for gad in chain:
            lenght += len(gad["gadget"]["bytes"])
        return lenght

    def get_best_gadget(self, gadgets):
        return sorted(gadgets, key=lambda gadget: len(gadget["gadget"]["bytes"]))[0]

    def read_file(self):
        try:
            ops = [line.rstrip('\n') for line in open(self.__rop_file)]
        except:
            print("[Error] Bad file %s" % self.__rop_file)
            sys.exit(-1)

        return ops

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

    def get_args_string(self):
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
