import argparse
import __main__
import os
import sys

from easyrop.parsers.parser import Parser
from easyrop.parsers.parse_exception import ParseException
from easyrop.registers import REGISTERS_X86

from pathlib import Path

class Args:
    def __init__(self, arguments):
        self._args = None
        self.parser = Parser()
        self.parse_arguments(arguments)

    def parse_arguments(self, arguments):
        parser = argparse.ArgumentParser()

        parser.add_argument("-v", "--version", action="store_true", help="display EasyROP's version")
        parser.add_argument("--binary", type=str, metavar="<path>", nargs='+', help="specify a list of binary paths to analyze")
        parser.add_argument("--depth", type=int, metavar="<bytes>", default=5, help="depth for search engine (default 5 bytes)")
        parser.add_argument("--all", action="store_true", help="disables the removal of duplicate gadgets")
        parser.add_argument("--nojop", action="store_true", help="disables JOP gadgets")
        parser.add_argument("--noretf", action="store_true", help="disables gadgets terminated in a far return (retf)")
        parser.add_argument("--op", type=str, metavar="<op>", help="search for operation")
        parser.add_argument("--reg-dst", type=str, metavar="<reg>", help="specify a destination reg to operation")
        parser.add_argument("--reg-src", type=str, metavar="<reg>", help="specify a source reg to operation")
        parser.add_argument("--ropchain", type=str, metavar="<file>", help="plain text file with rop chains")

        self._args = parser.parse_args(arguments)
        self.check_args()

    def check_args(self):
        if self._args.binary:
            self.check_files(self._args.binary)
        if self._args.op:
            self.parser.get_operation(self._args.op)
            if self._args.reg_dst is not None and self._args.reg_dst not in REGISTERS_X86:
                print("%s: '%s': Not a valid register" % (os.path.basename(__main__.__file__), self._args.reg_dst))
                sys.exit(-1)
            if self._args.reg_src is not None and self._args.reg_src not in REGISTERS_X86:
                print("%s: '%s': Not a valid register" % (os.path.basename(__main__.__file__), self._args.reg_src))
                sys.exit(-1)


    def check_files(self, binaries):
        for binary in binaries:
            file = Path(binary)
            if not file.is_file():
                print("%s: '%s': Not a file" % (os.path.basename(__main__.__file__), os.path.realpath(binary)))
                raise FileNotFoundError

    def get_args(self):
        return self._args
