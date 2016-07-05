import argparse
import sys

from easyrop.version import *


class Args:
    def __init__(self):
        self.__args = None
        arguments = sys.argv[1:]

        self.__parse(arguments)

    def __parse(self, arguments):
        parser = argparse.ArgumentParser()

        parser.add_argument("-v", "--version", action="store_true", help="Display EasyROP's version")
        parser.add_argument("--binary", type=str, metavar="<path>", help="Specify a binary path to analyze")
        parser.add_argument("--depth", type=int, metavar="<bytes>", default=10, help="Depth for search engine (default 10 bytes)")
        parser.add_argument("--all", action="store_true", help="Disables the removal of duplicate gadgets")
        parser.add_argument("--op", type=str, metavar="<op>", help="Search for operation: [lc, move, load, store, add, sub, xor, not, and, or, cond]")
        parser.add_argument("--reg-src", type=str, metavar="<reg>", help="Specify a source reg to operation")
        parser.add_argument("--reg-dst", type=str, metavar="<reg>", help="Specify a destination reg to operation")
        parser.add_argument("--ropchain", action="store_true", help="Enables ropchain generation to search for operation")

        self.__args = parser.parse_args(arguments)
        self.__check_args()
        self.__do_opcodes()

    def __do_opcodes(self):
        op = self.__args.op
        if op and not (op == "lc" or op == "move" or op == "load" or op == "store" or op == "xor" or op == "not" or op == "add"
                or op == "sub" or op == "and" or op == "or" or op == "cond"):
            print("[Error] Unsupported operation. op must to be: [lc, move, load, store, add, sub, xor, not, and, or, cond]")
            sys.exit(-1)

    def __check_args(self):
        if self.__args.version:
            self.__print_version()
            sys.exit(0)

        elif not self.__args.binary:
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

    def __print_version(self):
        print("Version: %s" % EASYROP_VERSION)
        print("Author: Daniel Uroz (based in Jonathan Salwan's ROPgadget)")

    def get_args(self):
        return self.__args
