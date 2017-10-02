"""
This class parses and checks the arguments passed to script
"""

import argparse
import sys
from easyrop.parsers.parser import Parser
from easyrop.version import *
from easyrop.parsers.parse_exception import ParseException


class Args:
    def __init__(self, arguments):
        self.__args = None
        self.__p = None
        try:
            self.__p = Parser(None)
        except ParseException:
            self.ops_string = "[Error] Couldn't read from gadgets source"
        self.parse(arguments)

    def parse(self, arguments):
        parser = argparse.ArgumentParser()

        parser.add_argument("-v", "--version", action="store_true", help="Display EasyROP's version")
        parser.add_argument("--binary", type=str, metavar="<path>", nargs='+', help="Specify a list of binary paths to analyze")
        parser.add_argument("--depth", type=int, metavar="<bytes>", default=5, help="Depth for search engine (default 5 bytes)")
        parser.add_argument("--all", action="store_true", help="Disables the removal of duplicate gadgets")
        if self.__p:
            ops = self.__p.get_all_ops()
            self.ops_string = ", ".join(ops)
        parser.add_argument("--op", type=str, metavar="<op>", help="Search for operation: " + self.ops_string)
        parser.add_argument("--reg-src", type=str, metavar="<reg>", help="Specify a source reg to operation")
        parser.add_argument("--reg-dst", type=str, metavar="<reg>", help="Specify a destination reg to operation")
        parser.add_argument("--ropchain", action="store_true", help="Enables ropchain generation to search for operation")
        parser.add_argument("--nojop", action="store_true", help="Disables JOP gadgets")
        parser.add_argument("--noretf", action="store_true", help="Disables gadgets terminated in a far return (retf)")
        parser.add_argument("--test-os", action="store_true", help="Analyze KnownDLLs of the computer to test viability of an attack (it takes long time)")
        parser.add_argument("--test-binary", type=str, metavar="<path>", help="Analyze a binary to test viability of an attack")
        parser.add_argument("--ropattack", type=str, metavar="<path>", help="Generate ROP attack from file")
        parser.add_argument("--dlls", action="store_true", help="Enable ROP attack search through KnownDLLs")

        self.__args = parser.parse_args(arguments)
        self.check_args()

    def check_args(self):
        if self.__args.version:
            self.print_version()
            sys.exit(0)

        elif not (self.__args.test_os or self.__args.test_binary):
            if self.__args.dlls and not self.__args.ropattack:
                print("[Error] dlls option without a ropattack file (--ropattack or help)")
                sys.exit(-1)
            elif not self.__args.binary and not (self.__args.ropattack and self.__args.dlls):
                print("[Error] Need a binary filename (--help)")
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
            elif self.__args.op and self.__args.ropchain:
                parser = Parser(self.__args.op)
                operation = parser.get_operation()
                if (operation.need_src() and not self.__args.reg_src) or (operation.need_dst() and not self.__args.reg_dst):
                    warnings = []
                    if operation.need_dst():
                        warnings += ["dst"]
                    if operation.need_src():
                        warnings += ["src"]
                    print("[Error] op \'%s\' need %s to generate ropchains" % (self.__args.op, " and ".join(warnings)))
                    sys.exit(-1)

            self.do_opcodes()

    def do_opcodes(self):
        if self.__args.op:
            if self.__p:
                ops = self.__p.get_all_ops()
                if self.__args.op not in ops:
                    print("[Error] op must be: %s" % self.ops_string)
                    sys.exit(-1)
            else:
                print(self.ops_string)
                sys.exit(-1)

    def print_version(self):
        print("Version: %s" % EASYROP_VERSION)
        print("Author: Daniel Uroz")

    def get_args(self):
        return self.__args
