import datetime
import os
from winreg import *
from capstone import *
from easyrop.args import Args
from easyrop.binaries.binary import Binary
from easyrop.core import Core


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


class Tester:
    def __init__(self):
        self.__gadgets = []
        self.__mode = REG_64

    def test(self):
        start = datetime.datetime.now()
        dlls = self.get_dlls()
        dirs = self.get_directories(dlls)
        dlls_path = self.get_absolute_paths(dirs, dlls)
        for d in dlls_path:
            self.test_binary(d, True)
        end = datetime.datetime.now() - start
        print('\nTime elapsed: %s' % str(end))

    def test_binary(self, file, silent=False):
        start = datetime.datetime.now()
        print("============================================")
        print("FILE: %s" % file)
        binary = Binary(file)
        if binary.get_arch_mode() == CS_MODE_32:
            self.__mode = REG_32
        self.__gadgets = self.get_gadgets(file)
        regs_found = self.load_constant(file)
        if self.load_memory(file, regs_found):
            if self.store_memory(file, regs_found):
                if self.add(file, regs_found):
                    if self.sub(file, regs_found):
                        if self.xor(file, regs_found):
                            if self.and_(file, regs_found):
                                if self.or_(file, regs_found):
                                    if self.cond1(file, regs_found):
                                        if self.cond2(file, regs_found):
                                            if self.move(file, regs_found):
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
        if sum(regs_found) < 2:
            return False
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
                            found = self.test_op(file, "add --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Add:")
                                print("\t%s <- %s + %s" % (regs[i][j], regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("Add: (ropchain)")
                                    print("\t%s <- %s + %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def sub(self, file, regs_found):
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
                            found = self.test_op(file, "sub --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Sub:")
                                print("\t%s <- %s - %s" % (regs[i][j], regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("Sub: (ropchain)")
                                    print("\t%s <- %s - %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def xor(self, file, regs_found):
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
                            found = self.test_op(file, "xor --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Xor:")
                                print("\t%s <- %s XOR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("Xor: (ropchain)")
                                    print("\t%s <- %s XOR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def and_(self, file, regs_found):
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
                            found = self.test_op(file, "and --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("And:")
                                print("\t%s <- %s AND %s" % (regs[i][j], regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("And: (ropchain)")
                                    print("\t%s <- %s AND %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def or_(self, file, regs_found):
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
                            found = self.test_op(file, "or --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Or:")
                                print("\t%s <- %s + %s" % (regs[i][j], regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("Or: (ropchain)")
                                    print("\t%s <- %s OR %s" % (regs[i][j], regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def cond1(self, file, regs_found):
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
                            found = self.test_op(file, "cond1 --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Contidional jumo:")
                                print("\tif %s < %s" % (regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("Conditional jump: (ropchain)")
                                    print("\tif %s < %s" % (regs[i][j], regs[i][k]))
                        k += 1
                    j += 1
                i += 1
        return found

    def cond2(self, file, regs_found):
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
                            found = self.test_op(file, "cond2 --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Contidional jump:")
                                print("\tthen esp + %s" % regs[i][j])
                    k += 1
                j += 1
            i += 1
        if not found:
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
                                    print("Conditional jump: (ropchain)")
                                    print("\tthen esp + %s" % regs[i][j])
                        k += 1
                    j += 1
                i += 1
        return found

    def move(self, file, regs_found):
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
                            found = self.test_op(file, "move --reg-dst %s --reg-src %s" % (regs[i][j], regs[i][k]))
                            if found:
                                print("Move:")
                                print("\t%s <- %s" % (regs[i][j], regs[i][k]))
                    k += 1
                j += 1
            i += 1
        if not found:
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

    def get_directories(self, dlls):
        directories = []
        windir = os.environ['windir']

        for dll in dlls:
            value = dll[VALUE_DATA]
            if "%SystemRoot%" in value:
                dll_path = value.replace("%SystemRoot%", windir)
            else:
                dll_path = windir + value
            if os.path.isdir(dll_path):
                directories += [dll]
        return directories

    def get_absolute_paths(self, dirs, dlls):
        dlls_paths = []
        windir = os.environ['windir']

        for d in dirs:
            for dll in dlls:
                value = d[VALUE_DATA]
                if "%SystemRoot%" in value:
                    path = value.replace("%SystemRoot%", windir)
                else:
                    path = windir + value
                dll_path = path + '\\' + dll[VALUE_DATA]
                if os.path.isfile(dll_path):
                    print(dll_path)
                    dlls_paths += [dll_path]
        return dlls_paths
