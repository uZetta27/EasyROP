import easyrop.args
import easyrop.binaries.binary
import easyrop.core


def main():
    import sys
    from easyrop.args import Args
    from easyrop.core import Core
    sys.exit(Core(Args().get_args()).analyze())
