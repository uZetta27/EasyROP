from winreg import *
import os
import datetime
from easyrop.core import Core
from easyrop.args import Args

VALUE_NAME = 0
VALUE_DATA = 1


class Tester:
    def __init__(self):
        self.__gadgets = []

    def test(self):
        start = datetime.datetime.now()
        dlls = self.get_dlls()
        dirs = self.get_directories(dlls)
        dlls_path = self.get_absolute_paths(dirs, dlls)
        for d in dlls_path:
            self.test_file(d, True)
        end = datetime.datetime.now() - start
        print('\nTime elapsed: %s' % str(end))

    def test_file(self, file, silent=False):
        start = datetime.datetime.now()
        print("============================================")
        print("FILE: %s" % file)
        print("Load constant: %s" % self.test_op(file, "lc", True))
        print("Move: %s" % self.test_op(file, "move"))
        print("Load from memory: %s" % self.test_op(file, "load"))
        print("Store to memory: %s" % self.test_op(file, "store"))
        print("Add: %s" % self.test_op(file, "add"))
        print("Sub: %s" % self.test_op(file, "sub"))
        print("And: %s" % self.test_op(file, "and"))
        print("Or: %s" % self.test_op(file, "or"))
        print("Xor: %s" % self.test_op(file, "xor"))
        print("Not: %s" % self.test_op(file, "not"))
        print("Conditional jump: %s" % self.test_op(file, "cond"))
        end = datetime.datetime.now() - start
        if not silent:
            print('\nTime elapsed: %s' % str(end))

    def test_op(self, file, op, first=False):
        argv = ('--binary %s --op %s' % (file, op)).split()
        args = Args(argv).get_args()
        core = Core(args)
        if first:
            self.__gadgets = core.analyze(True)
            if len(self.__gadgets) != 0:
                return True
        else:
            gadgets = core.search_operation(self.__gadgets, args.op, args.reg_src, args.reg_dst)
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
            dll_path = windir + dll[VALUE_DATA]
            if os.path.isdir(dll_path):
                directories += [dll]
        return directories

    def get_absolute_paths(self, dirs, dlls):
        dlls_paths = []
        windir = os.environ['windir']

        for d in dirs:
            for dll in dlls:
                dll_path = windir + d[VALUE_DATA] + '\\' + dll[VALUE_DATA]
                if os.path.isfile(dll_path):
                    dlls_paths += [dll_path]
        return dlls_paths
