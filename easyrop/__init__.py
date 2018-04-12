import sys

from easyrop.args import Args
from easyrop.binaries.binary import Binary
from easyrop.version import EASYROP_VERSION
from easyrop.core import Core
from easyrop.op_searcher import OpSearcher
from easyrop.rop_generator import RopGenerator

from easyrop.binaries.binary_exception import BinaryException
from easyrop.parsers.parse_exception import ParseException

def main():
    try:
        args = Args(sys.argv[1:]).get_args()
        if args.version:
            print_version()
        elif args.binary:
            if args.ropchain:
                print_ropchains(RopGenerator(args, debug=True).analyze())
            else:
                search_gadgets(args)
    except (FileNotFoundError, AttributeError, BinaryException, ParseException):
        sys.exit(-1)

def search_gadgets(args):
    total = 0
    for binary in args.binary:
        bin_ = Binary(binary)
        gadgets = Core(bin_, args).analyze()
        if args.op:
            gadgets = OpSearcher(bin_, args.op, args.reg_dst, args.reg_src).filter_gadgets(gadgets)
        total += len(gadgets)
        print_gadgets(gadgets)

    print_total(total)

def print_total(total):
    total_string = "Total: %s gadgets" % "{:,}".format(total)
    if total > 0:
        print('-' * len(total_string))
    print(total_string)

def print_gadgets(gadgets):
    for gad in gadgets:
        print(format_gadget(gad))

def format_gadget(gad):
    values = ('(' + ', '.join(gad["values"]) + ')').replace('()', '')
    return "[%s @ %s]: %s %s" % (gad["file"], hex(gad["vaddr"]), gad["gadget"], values)

def print_ropchains(ropchains):
    for ropchain in ropchains:
        print("\n%s" % ropchain["op"]["original"])
        for gadget in ropchain["gadgets"]:
            print("\t%s" % format_gadget(gadget))

def print_version():
    print("Version: %s" % EASYROP_VERSION)
    print("Author: urzu")
