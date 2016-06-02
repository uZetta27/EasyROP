import argparse
import sys

from easyrop.version import *
from capstone.x86_const import *


class Args:
    def __init__(self):
        self.__args = None
        arguments = sys.argv[1:]

        self.__parse(arguments)

    def __parse(self, arguments):
        parser = argparse.ArgumentParser()

        parser.add_argument("-v", "--version", action="store_true", help="Display EasyROP's version")
        parser.add_argument("--binary", type=str, metavar="<path>", help="Specify a binary path to analyze")
        parser.add_argument("--folder", type=str, metavar="<path>", help="Specify a folder path to analyze")
        parser.add_argument("--depth", type=int, metavar="<bytes>", default=10, help="Depth for search engine (default 10 bytes)")
        parser.add_argument("--op", type=str, metavar="<op>", help="Search for operation: [lc, move, load, store, xor, not, add, sub, and, or, cond]")
        parser.add_argument("--reg", type=str, metavar="<reg>", help="Specify a reg base to operation")

        self.__args = parser.parse_args(arguments)
        self.__check_args()
        self.__do_opcodes()

    def __do_opcodes(self):
        op = self.__args.op
        if op == "lc":
            self.__args.op = X86_INS_POP
        elif op == "move":
            self.__args.op = X86_INS_MOV
        elif op == "load":
            self.__args.op = X86_INS_LDS
        elif op == "store":
            self.__args.op = X86_INS_STD
        elif op == "xor":
            self.__args.op = X86_INS_XOR
        elif op == "not":
            self.__args.op = X86_INS_NOT
        elif op == "add":
            self.__args.op = X86_INS_ADD
        elif op == "sub":
            self.__args.op = X86_INS_SUB
        elif op == "and":
            self.__args.op = X86_INS_AND
        elif op == "or":
            self.__args.op = X86_INS_OR
        elif op == "cond":
            self.__args.op = X86_INS_CMP
        else:
            print("[Error] Unsupported operation. op must to be: [lc, move, load, store, xor, not, add, sub, and, or, cond]")
            sys.exit(-1)

    def __check_args(self):
        if self.__args.version:
            self.__print_version()
            sys.exit(0)

        elif not self.__args.binary and not self.__args.folder:
            print("[Error] Need a binary/folder filename (--binary, --folder or --help)")
            sys.exit(-1)

        elif self.__args.depth < 2:
            print("[Error] The depth must be >= 2")
            sys.exit(-1)

        elif not self.__args.op:
            print("[Error] Need an operation (--op or --help)")
            sys.exit(-1)

        elif not self.__args.op and self.__args.reg:
            print("[Error] reg specified without an opcode (--help)")
            sys.exit(-1)

    def __print_version(self):
        print("Version: %s" % EASYROP_VERSION)
        print("Author: Daniel Uroz Hinarejos (based in Jonathan Salwan's ROPgadget)")

    def get_args(self):
        return self.__args
