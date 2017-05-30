"""
This class provides functions to get the most frequent subset of KnownDLLs
"""

import os
import sys

# Import only if it's a Windows system
if 'nt' in sys.builtin_module_names:
    from winreg import *

VALUE_NAME = 0
VALUE_DATA = 1

# Most common DLLs in different Windows versions
common_dlls = ["kernel32.dll", "rpcrt4.dll", "ole32.dll", "shell32.dll", "advapi32.dll", "user32.dll", "gdi32.dll",
               "comdlg32.dll", "msvcrt.dll", "wldap32.dll", "shlwapi.dll", "ws2_32.dll", "setuapi.dll", "psapi.dll"]


class KnownDlls:
    def __init__(self):
        if 'nt' not in sys.builtin_module_names:
            print('[Error] No Windows system')
            sys.exit(-1)

    def get_dlls(self):
        """
        This function retrieves the most common subset of KnownDLLs of the host system
        :return: list of DLLs of the host system
        """
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
        """
        Get full path of system DLLs
        :param dlls: DLLs names
        :return: full path to DLLs
        """
        dlls_paths = []
        windir = os.environ['windir']
        system32 = os.sep + "system32" + os.sep

        for c in common_dlls:
            for dll in dlls:
                if dll[VALUE_DATA].lower() == c:
                    dll_path = windir + system32 + dll[VALUE_DATA]
                    if os.path.isfile(dll_path):
                        dlls_paths += [dll_path]

        return dlls_paths

