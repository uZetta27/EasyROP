


def main():
    import sys
    from easyrop.args import Args
    from easyrop.core import Core
    from easyrop.tester import Tester

    args = Args(sys.argv[1:]).get_args()

    if args.test_binary:
        Tester().test_binary(args.test_binary)
    elif args.test:
        Tester().test()
    else:
        sys.exit(Core(args).analyze())
