import easyrop.args
import easyrop.binaries.binary
import easyrop.core
import easyrop.tester


def main():
    import sys
    from easyrop.args import Args
    from easyrop.core import Core
    from easyrop.tester import Tester

    args = Args(sys.argv[1:]).get_args()

    if args.test_file:
        Tester().test_file(args.test_file)
    elif args.test:
        Tester().test()
    else:
        sys.exit(Core(args).analyze())
