import os
import random
import sys
from argparse import ArgumentParser, BooleanOptionalAction

from train import train


def main(argv) -> int:
    parser = ArgumentParser()
    parser.add_argument("-d",
                        "--data",
                        nargs="?",
                        help="CredData location",
                        dest="cred_data_location",
                        metavar="PATH",
                        required=True)
    parser.add_argument("-j",
                        "--jobs",
                        help="number of parallel processes to use (default: 4)",
                        default=4,
                        dest="jobs",
                        metavar="POSITIVE_INT")
    parser.add_argument("-e",
                        "--epochs",
                        help="maximal epochs to train (default: 100)",
                        default=100,
                        dest="epochs",
                        metavar="POSITIVE_INT")
    parser.add_argument("-b",
                        "--batch_size",
                        help="batch size (default: 256)",
                        default=256,
                        dest="batch_size",
                        metavar="POSITIVE_INT")
    parser.add_argument("-p",
                        "--patience",
                        help="early stopping patience (default: 5)",
                        default=5,
                        dest="patience",
                        metavar="POSITIVE_INT")
    parser.add_argument("--doc", help="use doc target", dest="doc_target", action=BooleanOptionalAction, default=False)
    parser.add_argument("--tuner",
                        help="use keras tuner",
                        dest="use_tuner",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--eval-test",
                        help="evaluate model for test dataset",
                        dest="eval_test",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--eval-train",
                        help="evaluate model for train dataset",
                        dest="eval_train",
                        action=BooleanOptionalAction,
                        default=False)
    parser.add_argument("--eval-full",
                        help="evaluate model for full dataset after train",
                        dest="eval_full",
                        action=BooleanOptionalAction,
                        default=False)
    args = parser.parse_args(argv[1:])

    fixed_seed = 20250919
    print(f"Fixed seed:{fixed_seed}", flush=True)
    random.seed(fixed_seed)

    print(args, flush=True)  # dbg
    _model_file_name = train(
        cred_data_location=args.cred_data_location,
        jobs=int(args.jobs),
        epochs=int(args.epochs),
        batch_size=int(args.batch_size),
        patience=int(args.patience),
        doc_target=bool(args.doc_target),
        use_tuner=bool(args.use_tuner),
        eval_test=bool(args.eval_test),
        eval_train=bool(args.eval_train),
        eval_full=bool(args.eval_full),
    )
    if os.path.exists(_model_file_name):
        # print in last line the name
        print(f"\nYou can find your model in:\n{_model_file_name}", flush=True)
        return 0
    print(f"Error: {_model_file_name}", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
