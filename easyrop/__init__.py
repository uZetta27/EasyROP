def main():
    import sys
    from easyrop.args import Args
    from easyrop.core import Core
    from easyrop.tester import Tester
    from easyrop.rop_generator import RopGenerator

    args = Args(sys.argv[1:]).get_args()

    if args.test_binary:
        Tester().test_binary(args.test_binary)
    elif args.test_os:
        Tester().test()
    elif args.ropattack:
        RopGenerator(args.binary, args.ropattack).generate()
    else:
        sys.exit(Core(args).analyze())
