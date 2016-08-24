import argparse
import sys

from easyrop.version import *
from easyrop.parsers.parser import Parser


class Args:
    def __init__(self, arguments):
        self.__args = None
        self.__p = Parser(None)
        self.parse(arguments)

    def parse(self, arguments):
        parser = argparse.ArgumentParser()

        parser.add_argument("-v", "--version", action="store_true", help="Display EasyROP's version")
        parser.add_argument("--binary", type=str, metavar="<path>", help="Specify a binary path to analyze")
        parser.add_argument("--depth", type=int, metavar="<bytes>", default=5, help="Depth for search engine (default 5 bytes)")
        parser.add_argument("--all", action="store_true", help="Disables the removal of duplicate gadgets")
        ops = self.__p.get_all_ops()
        ops_string = ", ".join(ops)
        parser.add_argument("--op", type=str, metavar="<op>", help="Search for operation: " + ops_string)
        parser.add_argument("--reg-src", type=str, metavar="<reg>", help="Specify a source reg to operation")
        parser.add_argument("--reg-dst", type=str, metavar="<reg>", help="Specify a destination reg to operation")
        parser.add_argument("--ropchain", action="store_true", help="Enables ropchain generation to search for operation")
        parser.add_argument("--nojop", action="store_true", help="Disables JOP gadgets")
        parser.add_argument("--noretf", action="store_true", help="Disables gadgets terminated in a far return (retf)")
        parser.add_argument("--test", action="store_true", help="Analyze KnownDLLs of the computer to test viability of an attack (it takes time: ~15 min)")
        parser.add_argument("--test-file", type=str, metavar="<path>", help="Analyze a file to test viability of an attack")

        self.__args = parser.parse_args(arguments)
        self.check_args()

    def check_args(self):
        if self.__args.version:
            self.print_version()
            sys.exit(0)

        elif not (self.__args.test or self.__args.test_file):
            if not self.__args.binary:
                print("[Error] Need a binary/folder filename (--binary or --help)")
                sys.exit(-1)

            elif self.__args.depth < 2:
                print("[Error] The depth must be >= 2")
                sys.exit(-1)

            elif not self.__args.op and (self.__args.reg_src or self.__args.reg_dst):
                print("[Error] reg specified without an opcode (--help)")
                sys.exit(-1)

            elif not self.__args.op and self.__args.ropchain:
                print("[Error] ropchain generation without an opcode (--help)")
                sys.exit(-1)

            self.do_opcodes()

    def do_opcodes(self):
        if self.__args.op:
            ops = self.__p.get_all_ops()
            if self.__args.op not in ops:
                ops_string = ", ".join(ops)
                print("[Error] op must be: %s" % ops_string)
                sys.exit(-1)

    def print_version(self):
        print("Version: %s" % EASYROP_VERSION)
        print("Author: Daniel Uroz")

    def get_args(self):
        return self.__args
