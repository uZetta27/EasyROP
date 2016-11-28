import datetime
import os
import sys
from capstone import *
from easyrop.args import Args
from easyrop.binaries.binary import Binary
from easyrop.core import Core

if 'nt' in sys.builtin_module_names:
    from winreg import *

VALUE_NAME = 0
VALUE_DATA = 1

REG_64 = 0
REG_32 = 1
REG_16 = 2
REG_8_H = 3
REG_8_L = 4

REGISTERS = [["rax", "rbx", "rcx", "rdx"],
             ["eax", "ebx", "ecx", "edx"],
             ["ax", "bx", "cx", "dx"],
             ["ah", "bh", "ch", "dh"],
             ["al", "bl", "cl", "dl"]]

DLLS = ["advapi32.dll", "comdlg32.dll", "gdi32.dll", "kernel32.dll", "msvcrt.dll", "ole32.dll", "psapi.dll",
        "rpcrt4.dll", "setupapi.dll", "shell32.dll", "shlwapi.dll", "user32.dll", "wldap32.dll", "ws2_32.dll"]


class Tester:
    def __init__(self):
        self.__gadgets = []
        self.__mode = REG_64

    def test(self):
        if 'nt' in sys.builtin_module_names:
            start = datetime.datetime.now()
            dlls = self.get_dlls()
            dlls_path = self.get_absolute_paths(dlls)
            for d in dlls_path:
                self.test_binary(d, True)
            end = datetime.datetime.now() - start
            print('\nTime elapsed: %s' % str(end))
        else:
            print('[Error] No Windows system')

    def test_binary(self, file, silent=False):
        start = datetime.datetime.now()
        print("============================================")
        print("FILE: %s" % file)
        binary = Binary(file)
        if binary.get_arch_mode() == CS_MODE_32:
            self.__mode = REG_32
        self.__gadgets = self.get_gadgets(file)
        regs_found = self.load_constant(file)
        turing_completeness = True
        result = self.load_memory(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.store_memory(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.add(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.sub(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.xor(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.and_(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.or_(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.not_(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.cond1(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.cond2(file, regs_found)
        turing_completeness = turing_completeness and result
        result = self.move(file, regs_found)
        turing_completeness = turing_completeness and result
        if turing_completeness:
            print("All operations found!")
        end = datetime.datetime.now() - start
        if not silent:
            print('\nTime elapsed: %s' % str(end))

    def load_constant(self, file):
        regs_found = [False, False, False, False]
        regs = REGISTERS[self.__mode:self.__mode+1]
        j = 0
        while j < len(regs[0]):
            found = self.test_op(file, "lc --reg-dst %s" % regs[0][j])
            if found:
                regs_found[j] = True
            j += 1
        if sum(regs_found) != 0:
            print("Load constant:")
            k = 0
            while k < len(regs_found):
                if regs_found[k]:
                    print("\t%s" % regs[0][k])
                k += 1
        return regs_found

    def load_memory(self, file, regs_found):
        found = self.test_op(file, "load")
        if found:
            found = False
            i = 0
            regs = REGISTERS[self.__mode:]
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if regs_found[k]:
                            found = self.test_op(file, "load --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Load from memory:")
                                print("\t%s <- [%s]" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def store_memory(self, file, regs_found):
        found = self.test_op(file, "store")
        if found:
            found = False
            i = 0
            regs = REGISTERS[self.__mode:]
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "store --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Store to memory:")
                                    print("\t[%s] <- %s" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def add(self, file, regs_found):
        found = self.test_op(file, "add")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "add --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Add:")
                                    print("\t%s <- %s + %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "add --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Add: (ropchain)")
                                    print("\t%s <- %s + %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def sub(self, file, regs_found):
        found = self.test_op(file, "sub")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "sub --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Sub:")
                                    print("\t%s <- %s - %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "sub --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Sub: (ropchain)")
                                    print("\t%s <- %s - %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def xor(self, file, regs_found):
        found = self.test_op(file, "xor")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "xor --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Xor:")
                                    print("\t%s <- %s XOR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "xor --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Xor: (ropchain)")
                                    print("\t%s <- %s XOR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def and_(self, file, regs_found):
        found = self.test_op(file, "and")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "and --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("And:")
                                    print("\t%s <- %s AND %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "and --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("And: (ropchain)")
                                    print("\t%s <- %s AND %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def or_(self, file, regs_found):
        found = self.test_op(file, "or")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "or --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Or:")
                                    print("\t%s <- %s OR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "or --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Or: (ropchain)")
                                    print("\t%s <- %s OR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def not_(self, file, regs_found):
        found = self.test_op(file, "not")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "not --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Not:")
                                    print("\t%s <- not %s" % (regs[i][j], regs[i][j]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "not --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Not: (ropchain)")
                                    print("\t%s <- not %s" % (regs[i][j], regs[i][j]))
                        k += 1
                    j += 1
                i += 1
        return found

    def cond1(self, file, regs_found):
        found = self.test_op(file, "cond1")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "cond1 --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Conditional jump (first task):")
                                    print("\tif %s < %s" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "cond1 --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Conditional jump (first task): (ropchain)")
                                    print("\tif %s < %s" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def cond2(self, file, regs_found):
        found = self.test_op(file, "cond2")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "cond2 --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Contidional jump (second task):")
                                    print("\tthen esp + %s" % regs[i][j])
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "cond2 --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Contidional jump (second task): (ropchain)")
                                    print("\tthen esp + %s" % regs[i][j])
                        k += 1
                    j += 1
                i += 1
        return found

    def move(self, file, regs_found):
        found = self.test_op(file, "move")
        regs = REGISTERS[self.__mode:]
        if found:
            found = False
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "move --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Move:")
                                    print("\t%s <- %s" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        else:
            i = 0
            while i < len(regs):
                j = 0
                while j < len(regs[i]):
                    k = 0
                    while k < len(regs[i]) and not found:
                        if j != k:
                            if regs_found[k]:
                                found = self.test_op(file, "move --reg-dst %s --reg-src %s --ropchain" % (regs[i][j], regs[i][k]))
                                if found:
                                    print("Move: (ropchain)")
                                    print("\t%s <- %s" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def get_gadgets(self, file):
        argv = ('--binary %s' % file).split()
        args = Args(argv).get_args()
        core = Core(args)
        return core.analyze(True)

    def test_op(self, file, op):
        argv = ('--binary %s --op %s' % (file, op)).split()
        args = Args(argv).get_args()
        core = Core(args)
        if "--ropchain" not in argv:
            gadgets = core.search_operation(self.__gadgets, args.op, args.reg_src, args.reg_dst)
        else:
            gadgets = core.search_ropchains(self.__gadgets, args.op, args.reg_src, args.reg_dst)
        if len(gadgets) != 0:
            return True
        return False

    def get_dlls(self):
        aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        aKey = OpenKey(aReg, "System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        dlls = []

        for i in range(QueryInfoKey(aKey)[1]):
            try:
                values = EnumValue(aKey, i)
                dlls += [values]
            except EnvironmentError:
                break
        return dlls

    def get_absolute_paths(self, dlls):
        dlls_paths = []
        windir = os.environ['windir']
        system32 = os.sep + "system32" + os.sep

        for dll in dlls:
            if dll[VALUE_DATA].lower() in DLLS:
                dll_path = windir + system32 + dll[VALUE_DATA]
                if os.path.isfile(dll_path):
                    dlls_paths += [dll_path]

        return dlls_paths
